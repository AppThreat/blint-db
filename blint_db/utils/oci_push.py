# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""
Streaming OCI registry push for blint-db artifacts.

The Python oras client reads each blob fully into memory before the PUT
(its provider does ``data=fd.read()``), so pushing a multi-GB blint.db
holds the whole database in RAM and gets OOM-killed inside memory-capped
environments. The Go oras CLI streams instead. This module implements the
same registry distribution protocol with constant memory:

- POST /v2/<repo>/blobs/uploads/ to open an upload session
- PUT <session>?digest=<sha256> with the file streamed as the body
- HEAD the blob first and skip uploads the registry already has
- PUT /v2/<repo>/manifests/<tag> with the assembled OCI manifest

The manifest produced matches what ``.oras/orasclient.py`` builds with
the Python oras client (same layer media types, title annotations and
config annotations), so pulls are unaffected.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import time
from pathlib import Path

import requests
from urllib.parse import urlsplit

CHUNK_SIZE = 8 * 1024 * 1024
UPLOAD_ATTEMPTS = 3
UPLOAD_RETRY_DELAY_SECONDS = 30
PROGRESS_LOG_INTERVAL = 1024 * 1024 * 1024

OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
EMPTY_CONFIG_MEDIA_TYPE = "application/vnd.unknown.config.v1+json"
EMPTY_CONFIG_BYTES = b"{}"

_CHALLENGE_PATTERN = re.compile(
    r'Bearer realm="(?P<realm>[^"]+)"(?:,service="(?P<service>[^"]+)")?'
)


class UploadFailedError(RuntimeError):
    """Raised when a registry request keeps failing after retries."""


class _ProgressReader(io.RawIOBase):
    """File wrapper that logs every gigabyte read so long uploads are visible."""

    def __init__(self, path: str | os.PathLike, label: str, size: int):
        self._file = open(path, "rb")
        self._label = label
        self._size = size
        self._read_bytes = 0
        self._next_mark = PROGRESS_LOG_INTERVAL

    def __len__(self) -> int:
        # requests uses this to set Content-Length and send the body with
        # a known length instead of chunked transfer-encoding, which
        # registries reject for blob uploads.
        return self._size

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        data = self._file.read(size)
        self._read_bytes += len(data)
        if self._read_bytes >= self._next_mark:
            print(
                f"uploaded {self._read_bytes / (1024 ** 3):.1f} GiB of {self._label}",
                flush=True,
            )
            while self._next_mark <= self._read_bytes:
                self._next_mark += PROGRESS_LOG_INTERVAL
        return data

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return self._file.seek(offset, whence)

    def tell(self) -> int:
        return self._file.tell()

    def fileno(self) -> int:
        return self._file.fileno()

    def close(self) -> None:
        self._file.close()
        super().close()


def digest_and_size(path: str | os.PathLike) -> tuple[str, int]:
    """Stream-hash a file, returning (sha256-with-prefix, size)."""
    hasher = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            hasher.update(chunk)
            size += len(chunk)
    return f"sha256:{hasher.hexdigest()}", size


def _parse_bearer_challenge(response: requests.Response) -> tuple[str, str]:
    header = response.headers.get("WWW-Authenticate", "")
    match = _CHALLENGE_PATTERN.search(header)
    if not match:
        raise RuntimeError(
            f"Registry did not offer a bearer challenge (status {response.status_code})"
        )
    return match.group("realm"), match.group("service") or ""


class RegistryClient:
    """Minimal OCI distribution client with challenge-driven bearer auth."""

    def __init__(
        self,
        registry: str,
        repository: str,
        username: str | None = None,
        password: str | None = None,
        insecure: bool = False,
    ):
        self.registry = registry
        self.repository = repository
        self.username = username
        self.password = password
        self.scheme = "http" if insecure else "https"
        self._token: str | None = None
        self._session = requests.Session()
        self._session.headers["User-Agent"] = (
            "blint-db-oci-push/1.0 (+https://github.com/AppThreat/blint-db)"
        )

    def _api_url(self, path: str) -> str:
        return f"{self.scheme}://{self.registry}{path}"

    def _fetch_token(self, scope: str) -> None:
        probe = self._session.get(self._api_url("/v2/"), timeout=(15, 60))
        realm, service = _parse_bearer_challenge(probe)
        params = {"scope": scope}
        if service:
            params["service"] = service
        auth = (self.username, self.password) if self.username else None
        response = self._session.get(realm, params=params, auth=auth, timeout=(15, 60))
        response.raise_for_status()
        payload = response.json()
        self._token = payload.get("token") or payload.get("access_token")

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        scope: str = "pull,push",
        **kwargs,
    ) -> requests.Response:
        url = path_or_url if path_or_url.startswith("http") else self._api_url(path_or_url)
        headers = dict(kwargs.pop("headers", None) or {})
        response = None
        for _ in range(UPLOAD_ATTEMPTS):
            if self._token:
                headers["Authorization"] = f"Bearer {self._token}"
            response = self._session.request(
                method, url, headers=headers, timeout=(15, 300), **kwargs
            )
            if response.status_code != 401:
                return response
            self._fetch_token(f"repository:{self.repository}:{scope}")
        return response

    def blob_exists(self, digest: str) -> bool:
        response = self.request(
            "HEAD", f"/v2/{self.repository}/blobs/{digest}", scope="pull"
        )
        return response.status_code == 200

    def _open_upload_session(self) -> str:
        response = self.request("POST", f"/v2/{self.repository}/blobs/uploads/")
        if response.status_code != 202:
            raise UploadFailedError(
                f"Upload session rejected ({response.status_code}): {response.text[:200]}"
            )
        location = response.headers.get("Location")
        if not location:
            raise UploadFailedError("Upload session response had no Location header")
        self._validate_upload_location(location)
        return location if location.startswith("http") else self._api_url(location)

    def _validate_upload_location(self, location: str) -> None:
        """
        Refuse upload sessions that move off the registry host or downgrade
        the scheme, so the bearer token is never forwarded anywhere else
        (mirrors oras-go's fix for GHSA-jxpm-75mh-9fp7; also covers
        registries that hand out pre-signed cross-host URLs).
        """
        parsed = urlsplit(location if "//" in location else f"{self.scheme}://{self.registry}{location}")
        registry_parsed = urlsplit(f"{self.scheme}://{self.registry}")
        default_ports = {"https": 443, "http": 80}

        def effective_port(split):
            return split.port or default_ports.get(split.scheme)

        if parsed.hostname != registry_parsed.hostname or effective_port(parsed) != effective_port(
            registry_parsed
        ):
            raise UploadFailedError(
                f"Upload location moved to a different host ({parsed.netloc}); refusing to continue"
            )
        if self.scheme == "https" and parsed.scheme == "http":
            raise UploadFailedError("Upload location downgraded https to http; refusing to continue")

    def _put_blob(self, blob_url: str, body, size: int, label: str) -> None:
        started = time.monotonic()
        response = self.request(
            "PUT",
            blob_url,
            headers={"Content-Type": "application/octet-stream"},
            data=body,
        )
        if response.status_code not in (200, 201, 202):
            raise UploadFailedError(
                f"PUT for {label} returned {response.status_code}: {response.text[:200]}"
            )
        elapsed = max(time.monotonic() - started, 1)
        print(
            f"{label}: uploaded {size / (1024 ** 2):.0f} MiB in "
            f"{elapsed / 60:.1f} min ({size / elapsed / (1024 ** 2):.0f} MiB/s)",
            flush=True,
        )

    def upload_blob(self, path: str | os.PathLike, digest: str, size: int) -> bool:
        """Stream a file as one blob. Returns False when the registry already had it."""
        label = Path(path).name
        if self.blob_exists(digest):
            print(f"{label}: blob already present ({digest[:19]}...)", flush=True)
            return False
        last_error = ""
        for attempt in range(1, UPLOAD_ATTEMPTS + 1):
            session_url = self._open_upload_session()
            separator = "&" if "?" in session_url else "?"
            body = _ProgressReader(path, label, size)
            try:
                self._put_blob(f"{session_url}{separator}digest={digest}", body, size, label)
                return True
            except (UploadFailedError, requests.RequestException) as exc:
                last_error = str(exc)
            finally:
                body.close()
            print(
                f"upload attempt {attempt}/{UPLOAD_ATTEMPTS} for {label} failed: {last_error}",
                flush=True,
            )
            if attempt < UPLOAD_ATTEMPTS:
                time.sleep(UPLOAD_RETRY_DELAY_SECONDS)
        raise UploadFailedError(
            f"Failed to upload {path} after {UPLOAD_ATTEMPTS} attempts: {last_error}"
        )

    def upload_bytes(self, payload: bytes, digest: str, label: str) -> bool:
        """Upload a small in-memory blob such as the manifest config."""
        if self.blob_exists(digest):
            return False
        session_url = self._open_upload_session()
        separator = "&" if "?" in session_url else "?"
        self._put_blob(f"{session_url}{separator}digest={digest}", payload, len(payload), label)
        return True

    def upload_manifest(self, manifest: dict, tag: str) -> str:
        payload = json.dumps(manifest).encode("utf-8")
        response = self.request(
            "PUT",
            f"/v2/{self.repository}/manifests/{tag}",
            headers={"Content-Type": manifest.get("mediaType", OCI_MANIFEST_MEDIA_TYPE)},
            data=payload,
        )
        if response.status_code not in (200, 201):
            raise UploadFailedError(
                f"Manifest push rejected ({response.status_code}): {response.text[:200]}"
            )
        return response.headers.get("Docker-Content-Digest", "")


def _descriptor(
    digest: str, size: int, media_type: str, annotations: dict | None = None
) -> dict:
    descriptor = {"mediaType": media_type, "digest": digest, "size": size}
    if annotations:
        descriptor["annotations"] = annotations
    return descriptor


def stream_push(
    target: str,
    files: list[tuple[str, str]],
    annotation_file: str | os.PathLike | None = None,
    username: str | None = None,
    password: str | None = None,
    insecure: bool = False,
) -> str:
    """
    Push files as OCI layers to ``target`` (``registry/repository:tag``).

    ``files`` is a list of ``(path, media_type)`` pairs; each file becomes
    one layer titled with its basename. ``annotation_file`` follows the
    oras annotation JSON conventions (``$config`` / ``$manifest`` keys).
    Returns the manifest digest reported by the registry.
    """
    if ":" not in target.rsplit("/", 1)[-1]:
        raise ValueError(f"Target must include a tag: {target}")
    registry_repo, tag = target.rsplit(":", 1)
    registry, repository = registry_repo.split("/", 1)

    annotations: dict = {}
    if annotation_file and Path(annotation_file).exists():
        annotations = json.loads(Path(annotation_file).read_text(encoding="utf-8"))
    config_annotations = annotations.get("$config") or {}
    manifest_annotations = annotations.get("$manifest") or {}

    client = RegistryClient(
        registry, repository, username=username, password=password, insecure=insecure
    )

    config_digest = "sha256:" + hashlib.sha256(EMPTY_CONFIG_BYTES).hexdigest()
    client.upload_bytes(EMPTY_CONFIG_BYTES, config_digest, "config")

    layers = []
    for path, media_type in files:
        file_path = Path(path)
        if not file_path.is_file():
            raise FileNotFoundError(f"{path} does not exist or is not a file")
        digest, size = digest_and_size(file_path)
        client.upload_blob(file_path, digest, size)
        layers.append(
            _descriptor(
                digest,
                size,
                media_type,
                {"org.opencontainers.image.title": file_path.name},
            )
        )

    manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST_MEDIA_TYPE,
        "config": _descriptor(
            config_digest,
            len(EMPTY_CONFIG_BYTES),
            EMPTY_CONFIG_MEDIA_TYPE,
            config_annotations,
        ),
        "layers": layers,
    }
    if manifest_annotations:
        manifest["annotations"] = manifest_annotations

    return client.upload_manifest(manifest, tag)
