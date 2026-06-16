from __future__ import annotations

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urljoin
from urllib.request import Request, urlopen

from blint_db import (
    ARCH,
    BLINT_DB_BOOTSTRAP_PATH,
    BUILD_JOBS,
    CARGO_CURATED_CRATES_FILE,
    CARGO_DEFAULT_PROFILE,
    CARGO_DEFAULT_TARGET,
    CARGO_EXECUTABLE,
    CARGO_EXTRA_BUILD_ARGS,
    CARGO_EXTRA_FETCH_ARGS,
    CARGO_HTTP_TIMEOUT,
    CARGO_REGISTRY_API,
    DEBUG_MODE,
    SYSTEM,
    logger,
)
from blint_db.handlers.language_handlers import BaseHandler
from blint_db.utils import is_exe

_CARGO_SKIP_DIRS = {"build", "deps", "examples", "incremental", ".fingerprint"}
_CARGO_UNSUPPORTED_SUFFIXES = {
    ".d",
    ".dSYM",
    ".o",
    ".obj",
    ".pdb",
    ".rmeta",
    ".rlib",
}
_CARGO_SUPPORTED_LIBRARY_SUFFIXES = {".a", ".dylib", ".dll", ".so", ".wasm"}


@dataclass(frozen=True, slots=True)
class CargoProjectSpec:
    crate: str
    version: str
    feature_profile: str | None = None
    profile: str = CARGO_DEFAULT_PROFILE
    features: tuple[str, ...] = ()
    default_features: bool = True
    bins: tuple[str, ...] = ()
    package: str | None = None
    target: str | None = CARGO_DEFAULT_TARGET
    source: str = "curated"

    @property
    def selector(self) -> str:
        selector = f"{self.crate}@{self.version}"
        if self.feature_profile:
            return f"{selector}#{self.feature_profile}"
        return selector


@dataclass(frozen=True, slots=True)
class CargoBuildResult:
    spec: CargoProjectSpec
    project_purl: str
    project_metadata: dict
    build_metadata: dict
    artifacts: list[str]
    source_root: Path
    target_dir: Path
    target_triplet: str | None
    target_os: str | None
    target_arch: str | None
    build_mode: str
    optimization: str | None
    strip_status: str = "unknown"


class CargoHandler(BaseHandler):
    strip = False

    def build(self, project_name):
        return build_cargo_project(resolve_cargo_project_spec(project_name))

    def find_executables(self, project_name):
        spec = resolve_cargo_project_spec(project_name)
        build_root = cargo_project_root(spec)
        target_dir = build_root / "target"
        target_triplet = spec.target or cargo_host_target()
        return find_cargo_artifacts(
            target_dir,
            target_triplet=target_triplet,
            profile=spec.profile,
        )

    def delete_project_files(self, project_name):
        shutil.rmtree(
            cargo_project_root(resolve_cargo_project_spec(project_name)),
            ignore_errors=True,
        )

    def get_project_list(self):
        return [project.selector for project in load_curated_cargo_projects()]


def _split_csv_list(raw_value: str | None) -> tuple[str, ...]:
    if not raw_value:
        return ()
    return tuple(part.strip() for part in re.split(r"[;,]", raw_value) if part.strip())


def _parse_bool(raw_value: str | None, *, default: bool = True) -> bool:
    if raw_value is None or raw_value == "":
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _slugify_selector(selector: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", selector)


def _parse_cargo_selector(selector: str) -> tuple[str, str | None, str | None]:
    normalized_selector = selector.strip()
    selector_without_profile, has_profile, feature_profile = (
        normalized_selector.partition("#")
    )
    crate, has_version, version = selector_without_profile.partition("@")
    return (
        crate.strip(),
        version.strip() if has_version else None,
        feature_profile.strip() if has_profile else None,
    )


def _crates_api_json(url: str) -> dict:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "blint-db/2.0",
        },
    )
    with urlopen(request, timeout=CARGO_HTTP_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def _download_file(url: str, destination: Path) -> None:
    request = Request(url, headers={"User-Agent": "blint-db/2.0"})
    with urlopen(request, timeout=CARGO_HTTP_TIMEOUT) as response:
        destination.write_bytes(response.read())


def _sha256_file(file_path: str | os.PathLike) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _profile_args(profile: str) -> list[str]:
    normalized = (profile or "release").strip().lower()
    if normalized in {"", "dev", "debug"}:
        return []
    if normalized == "release":
        return ["--release"]
    return ["--profile", profile]


def _feature_args(spec: CargoProjectSpec) -> list[str]:
    args: list[str] = []
    if not spec.default_features:
        args.append("--no-default-features")
    if spec.features:
        args.extend(["--features", ",".join(spec.features)])
    if spec.package:
        args.extend(["--package", spec.package])
    for binary_name in spec.bins:
        args.extend(["--bin", binary_name])
    if spec.target:
        args.extend(["--target", spec.target])
    return args


def cargo_fetch_command(
    manifest_path: str | os.PathLike, spec: CargoProjectSpec, *, locked: bool
) -> list[str]:
    command = [
        CARGO_EXECUTABLE,
        "fetch",
        "--manifest-path",
        str(manifest_path),
    ]
    if locked:
        command.append("--locked")
    if spec.target:
        command.extend(["--target", spec.target])
    command.extend(CARGO_EXTRA_FETCH_ARGS)
    return command


def cargo_metadata_command(
    manifest_path: str | os.PathLike, spec: CargoProjectSpec, *, locked: bool
) -> list[str]:
    command = [
        CARGO_EXECUTABLE,
        "metadata",
        "--format-version",
        "1",
        "--manifest-path",
        str(manifest_path),
    ]
    if locked:
        command.append("--locked")
    if not spec.default_features:
        command.append("--no-default-features")
    if spec.features:
        command.extend(["--features", ",".join(spec.features)])
    if spec.target:
        command.extend(["--filter-platform", spec.target])
    return command


def cargo_build_command(
    manifest_path: str | os.PathLike,
    spec: CargoProjectSpec,
    *,
    locked: bool,
    frozen: bool,
) -> list[str]:
    command = [
        CARGO_EXECUTABLE,
        "build",
        "--message-format=json-render-diagnostics",
        "--manifest-path",
        str(manifest_path),
        *_profile_args(spec.profile),
    ]
    if locked:
        command.append("--locked")
    if frozen:
        command.append("--frozen")
    command.extend(_feature_args(spec))
    command.extend(CARGO_EXTRA_BUILD_ARGS)
    return command


def cargo_project_root(spec: CargoProjectSpec) -> Path:
    return BLINT_DB_BOOTSTRAP_PATH / "cargo" / _slugify_selector(spec.selector)


def cargo_environment(build_root: str | os.PathLike) -> dict[str, str]:
    root = Path(build_root)
    env = os.environ.copy()
    env["CARGO_HOME"] = str(root / "cargo-home")
    env["CARGO_TARGET_DIR"] = str(root / "target")
    env["CARGO_INCREMENTAL"] = "0"
    env.setdefault("CARGO_TERM_COLOR", "never")
    env.setdefault("RUST_BACKTRACE", "1")
    return env


def cargo_host_target() -> str | None:
    try:
        completed = subprocess.run(
            ["rustc", "-vV"],
            capture_output=True,
            check=False,
            encoding="utf-8",
        )
    except (FileNotFoundError, OSError):
        return None
    for line in (completed.stdout or "").splitlines():
        if line.startswith("host: "):
            return line.split(":", 1)[1].strip() or None
    return None


def _normalize_target_arch(raw_arch: str | None) -> str | None:
    if not raw_arch:
        return ARCH
    mapping = {
        "x86_64": "x64",
        "aarch64": "arm64",
    }
    return mapping.get(raw_arch, raw_arch)


def _normalize_target_os(raw_target: str | None) -> str | None:
    if not raw_target:
        return SYSTEM
    lowered = raw_target.lower()
    if "darwin" in lowered or "apple" in lowered:
        return "osx"
    if "linux" in lowered:
        return "linux"
    if "windows" in lowered or "msvc" in lowered:
        return "windows"
    if "android" in lowered:
        return "android"
    if lowered.startswith("wasm"):
        return "wasm"
    return SYSTEM


def classify_target_triplet(
    target_triplet: str | None,
) -> tuple[str | None, str | None, str | None]:
    if not target_triplet:
        return SYSTEM, ARCH, None
    parts = target_triplet.split("-")
    raw_arch = parts[0] if parts else None
    return (
        _normalize_target_os(target_triplet),
        _normalize_target_arch(raw_arch),
        target_triplet,
    )


def load_curated_cargo_projects(
    file_path: str | os.PathLike | None = None,
) -> list[CargoProjectSpec]:
    csv_path = Path(file_path or CARGO_CURATED_CRATES_FILE)
    if not csv_path.exists():
        return []
    projects: list[CargoProjectSpec] = []
    with open(csv_path, "r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            crate = (row.get("crate") or "").strip()
            version = (row.get("version") or "").strip()
            if not crate or not version:
                continue
            projects.append(
                CargoProjectSpec(
                    crate=crate,
                    version=version,
                    feature_profile=(row.get("feature_profile") or "").strip() or None,
                    profile=(row.get("profile") or CARGO_DEFAULT_PROFILE).strip()
                    or CARGO_DEFAULT_PROFILE,
                    features=_split_csv_list(row.get("features")),
                    default_features=_parse_bool(
                        row.get("default_features"), default=True
                    ),
                    bins=_split_csv_list(row.get("bins")),
                    package=(row.get("package") or "").strip() or None,
                    target=(row.get("target") or "").strip() or CARGO_DEFAULT_TARGET,
                    source="curated",
                )
            )
    return projects


def get_cargo_projects(
    file_path: str | os.PathLike | None = None,
) -> list[CargoProjectSpec]:
    return load_curated_cargo_projects(file_path=file_path)


def resolve_cargo_project_spec(
    selector: str,
    *,
    curated_projects: list[CargoProjectSpec] | None = None,
) -> CargoProjectSpec:
    normalized_selector = selector.strip()
    projects = (
        curated_projects
        if curated_projects is not None
        else load_curated_cargo_projects()
    )
    for project in projects:
        if project.selector == normalized_selector:
            return project

    crate, version, feature_profile = _parse_cargo_selector(normalized_selector)
    if version is not None:
        matches = [
            project
            for project in projects
            if project.crate == crate and project.version == version
        ]
        if feature_profile is not None:
            matches = [
                project
                for project in matches
                if project.feature_profile == feature_profile
            ]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ValueError(
                f"Cargo selector '{selector}' is ambiguous. Use one of: {', '.join(project.selector for project in matches)}"
            )
        if not crate or not version:
            raise ValueError(
                f"Invalid cargo selector '{selector}'. Expected crate@version."
            )
        return CargoProjectSpec(
            crate=crate,
            version=version,
            feature_profile=feature_profile,
            source="manual",
        )
    matches = [project for project in projects if project.crate == crate]
    if feature_profile is not None:
        matches = [
            project for project in matches if project.feature_profile == feature_profile
        ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ValueError(
            f"Unknown cargo crate '{selector}'. Use crate@version or one of the curated entries."
        )
    raise ValueError(
        f"Cargo crate selector '{selector}' is ambiguous. Use one of: {', '.join(project.selector for project in matches)}"
    )


_TOP_CRATES_CSV_FIELDS = (
    "crate",
    "version",
    "feature_profile",
    "profile",
    "default_features",
    "features",
    "bins",
    "package",
    "target",
)


def _top_crate_version(crate_payload: dict) -> str | None:
    """Return the best version string to build for a crates.io crate payload."""
    for key in (
        "max_stable_version",
        "newest_version",
        "max_version",
        "default_version",
    ):
        value = (crate_payload.get(key) or "").strip()
        if value:
            return value
    return None


def fetch_top_crates(count: int) -> list[dict]:
    """Return the most downloaded crates from crates.io, newest stable version each.

    Args:
        count: Number of crates to return, ordered by all-time download count.

    Returns:
        A list of row dictionaries using the curated crate CSV schema. Crates
        without a resolvable version are skipped.
    """
    if count <= 0:
        return []
    per_page = min(100, count)
    rows: list[dict] = []
    seen: set[str] = set()
    page = 1
    api_root = CARGO_REGISTRY_API.rstrip("/")
    while len(rows) < count:
        url = f"{api_root}/api/v1/crates?page={page}&per_page={per_page}&sort=downloads"
        payload = _crates_api_json(url)
        crates = payload.get("crates") or []
        if not crates:
            break
        for crate_payload in crates:
            name = (crate_payload.get("name") or "").strip()
            version = _top_crate_version(crate_payload)
            if not name or not version or name in seen:
                continue
            seen.add(name)
            rows.append(
                {
                    "crate": name,
                    "version": version,
                    "feature_profile": "",
                    "profile": CARGO_DEFAULT_PROFILE,
                    "default_features": "true",
                    "features": "",
                    "bins": "",
                    "package": "",
                    "target": "",
                }
            )
            if len(rows) >= count:
                break
        page += 1
    return rows


def write_top_crates_csv(count: int, output_path: str | os.PathLike) -> int:
    """Fetch the top crates and persist them as a curated-style CSV file.

    Args:
        count: Number of crates to fetch.
        output_path: Destination CSV path.

    Returns:
        The number of crate rows written.
    """
    rows = fetch_top_crates(count)
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with open(destination, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=_TOP_CRATES_CSV_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    logger.info("Wrote %d top crates to %s", len(rows), destination)
    return len(rows)


def crates_io_release(spec: CargoProjectSpec) -> dict:
    payload = _crates_api_json(
        f"{CARGO_REGISTRY_API.rstrip('/')}/api/v1/crates/{quote(spec.crate, safe='')}/{quote(spec.version, safe='')}"
    )
    version_payload = payload.get("version") or {}
    crate_payload = payload.get("crate") or {}
    download_url = (
        version_payload.get("dl_path")
        or f"/api/v1/crates/{spec.crate}/{spec.version}/download"
    )
    if download_url.startswith("/"):
        download_url = urljoin(
            CARGO_REGISTRY_API.rstrip("/") + "/", download_url.lstrip("/")
        )
    return {
        "crate": crate_payload,
        "version": version_payload,
        "download_url": download_url,
        "checksum": version_payload.get("checksum"),
    }


def download_and_extract_crate(
    spec: CargoProjectSpec, build_root: str | os.PathLike
) -> tuple[dict, Path, Path]:
    release_info = crates_io_release(spec)
    root = Path(build_root)
    downloads_dir = root / "downloads"
    source_dir = root / "source"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(source_dir, ignore_errors=True)
    source_dir.mkdir(parents=True, exist_ok=True)
    archive_path = downloads_dir / f"{spec.crate}-{spec.version}.crate"
    _download_file(release_info["download_url"], archive_path)
    checksum = release_info.get("checksum")
    digest = _sha256_file(archive_path)
    if checksum and digest != checksum:
        raise RuntimeError(
            f"Checksum mismatch for {spec.selector}: expected {checksum}, got {digest}"
        )
    with tarfile.open(archive_path, "r:gz") as archive:
        archive.extractall(source_dir)
    manifest_root = locate_manifest_root(source_dir, spec)
    return release_info, archive_path, manifest_root


def locate_manifest_root(source_dir: str | os.PathLike, spec: CargoProjectSpec) -> Path:
    root = Path(source_dir)
    preferred = root / f"{spec.crate}-{spec.version}"
    if (preferred / "Cargo.toml").exists():
        return preferred
    if (root / "Cargo.toml").exists():
        return root
    candidates = sorted(path.parent for path in root.rglob("Cargo.toml"))
    if len(candidates) == 1:
        return candidates[0]
    raise RuntimeError(f"Unable to locate Cargo.toml for {spec.selector}")


def _select_package_id(cargo_metadata: dict, spec: CargoProjectSpec) -> str | None:
    if spec.package:
        for package in cargo_metadata.get("packages") or []:
            if package.get("name") == spec.package:
                return package.get("id")
    root_package = cargo_metadata.get("resolve", {}).get("root")
    if root_package:
        return root_package
    root_package_metadata = cargo_metadata.get("root_package") or {}
    return root_package_metadata.get("id")


def _root_package_metadata(cargo_metadata: dict, package_id: str | None) -> dict:
    for package in cargo_metadata.get("packages") or []:
        if package.get("id") == package_id:
            return package
    if spec_root := cargo_metadata.get("root_package"):
        return spec_root
    return {}


def _run_cargo_command(
    command: list[str],
    *,
    cwd: str | os.PathLike,
    env: dict[str, str],
    capture_output: bool = True,
) -> subprocess.CompletedProcess:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=capture_output,
        check=False,
        encoding="utf-8",
    )
    if DEBUG_MODE and result.stderr:
        logger.debug("%s", result.stderr)
    return result


def cargo_metadata_for_project(
    manifest_path: str | os.PathLike,
    spec: CargoProjectSpec,
    *,
    cwd: str | os.PathLike,
    env: dict[str, str],
    locked: bool,
) -> dict:
    command = cargo_metadata_command(manifest_path, spec, locked=locked)
    result = _run_cargo_command(command, cwd=cwd, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"cargo metadata failed for {spec.selector}")
    payload = json.loads(result.stdout or "{}")
    package_id = _select_package_id(payload, spec)
    if package_id:
        payload["root_package"] = _root_package_metadata(payload, package_id)
    return payload


def _is_supported_cargo_artifact(file_path: str | os.PathLike) -> bool:
    path_obj = Path(file_path)
    if not path_obj.exists() or not path_obj.is_file():
        return False
    if any(part in _CARGO_SKIP_DIRS for part in path_obj.parts):
        return False
    if any(str(path_obj).endswith(suffix) for suffix in _CARGO_UNSUPPORTED_SUFFIXES):
        return False
    if path_obj.suffix in _CARGO_SUPPORTED_LIBRARY_SUFFIXES:
        return True
    if path_obj.suffix.lower() == ".exe":
        return True
    return is_exe(str(path_obj))


def artifacts_from_cargo_messages(
    message_stream: str, *, root_package_id: str | None = None
) -> list[str]:
    artifacts: list[str] = []
    seen: set[str] = set()
    for raw_line in (message_stream or "").splitlines():
        line = raw_line.strip()
        if not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if payload.get("reason") != "compiler-artifact":
            continue
        if root_package_id and payload.get("package_id") != root_package_id:
            continue
        candidate_paths = []
        executable = payload.get("executable")
        if executable:
            candidate_paths.append(executable)
        candidate_paths.extend(payload.get("filenames") or [])
        for candidate in candidate_paths:
            candidate_path = str(candidate)
            if candidate_path in seen or not _is_supported_cargo_artifact(
                candidate_path
            ):
                continue
            seen.add(candidate_path)
            artifacts.append(candidate_path)
    return sorted(artifacts)


def _profile_root_candidates(
    target_dir: Path, *, profile: str, target_triplet: str | None = None
) -> list[Path]:
    normalized_profile = (
        "debug" if (profile or "").strip().lower() in {"", "dev", "debug"} else profile
    )
    candidates = [target_dir / normalized_profile]
    if target_triplet:
        candidates.insert(0, target_dir / target_triplet / normalized_profile)
    return candidates


def find_cargo_artifacts(
    target_dir: str | os.PathLike,
    *,
    target_triplet: str | None = None,
    profile: str = CARGO_DEFAULT_PROFILE,
) -> list[str]:
    root = Path(target_dir)
    if not root.exists():
        return []
    artifacts: dict[str, Path] = {}
    for profile_root in _profile_root_candidates(
        root, profile=profile, target_triplet=target_triplet
    ):
        if not profile_root.exists():
            continue
        for path_obj in profile_root.rglob("*"):
            if not _is_supported_cargo_artifact(path_obj):
                continue
            resolved = str(path_obj.resolve())
            artifacts.setdefault(resolved, path_obj)
    return sorted(str(path) for path in artifacts.values())


def build_cargo_project(spec: CargoProjectSpec) -> CargoBuildResult:
    if shutil.which(str(CARGO_EXECUTABLE)) is None:
        raise ModuleNotFoundError(f"Cargo executable was not found: {CARGO_EXECUTABLE}")

    build_root = cargo_project_root(spec)
    build_root.mkdir(parents=True, exist_ok=True)
    env = cargo_environment(build_root)
    release_info, archive_path, source_root = download_and_extract_crate(
        spec, build_root
    )
    manifest_path = source_root / "Cargo.toml"
    initial_lockfile = source_root / "Cargo.lock"
    had_lockfile = initial_lockfile.exists()

    fetch_command = None
    if had_lockfile:
        fetch_command = cargo_fetch_command(manifest_path, spec, locked=True)
        fetch_result = _run_cargo_command(fetch_command, cwd=source_root, env=env)
        if fetch_result.returncode != 0:
            raise RuntimeError(f"cargo fetch failed for {spec.selector}")

    cargo_metadata = cargo_metadata_for_project(
        manifest_path,
        spec,
        cwd=source_root,
        env=env,
        locked=had_lockfile,
    )
    package_id = _select_package_id(cargo_metadata, spec)
    root_package = _root_package_metadata(cargo_metadata, package_id)

    build_command = cargo_build_command(
        manifest_path,
        spec,
        locked=had_lockfile,
        frozen=had_lockfile,
    )
    build_result = _run_cargo_command(build_command, cwd=source_root, env=env)
    if build_result.returncode != 0:
        raise RuntimeError(f"cargo build failed for {spec.selector}")

    target_triplet = spec.target or cargo_host_target()
    target_os, target_arch, normalized_triplet = classify_target_triplet(target_triplet)
    target_dir = Path(env["CARGO_TARGET_DIR"])
    artifacts = artifacts_from_cargo_messages(
        build_result.stdout or "",
        root_package_id=package_id,
    )
    if not artifacts:
        artifacts = find_cargo_artifacts(
            target_dir,
            target_triplet=target_triplet,
            profile=spec.profile,
        )

    project_metadata = {
        "description": root_package.get("description")
        or (release_info.get("crate") or {}).get("description"),
        "documentation": root_package.get("documentation"),
        "homepage": root_package.get("homepage")
        or (release_info.get("crate") or {}).get("homepage"),
        "license": root_package.get("license")
        or (release_info.get("version") or {}).get("license"),
        "name": root_package.get("name") or spec.crate,
        "repository": root_package.get("repository")
        or (release_info.get("crate") or {}).get("repository"),
        "rust_version": root_package.get("rust_version")
        or (release_info.get("version") or {}).get("rust_version"),
        "targets": [
            {
                "name": target.get("name"),
                "kind": target.get("kind"),
                "crate_types": target.get("crate_types"),
            }
            for target in (root_package.get("targets") or [])
        ],
        "crate_version": spec.version,
        "keywords": root_package.get("keywords"),
        "categories": root_package.get("categories"),
    }
    lock_path = source_root / "Cargo.lock"
    build_metadata = {
        "crate": spec.crate,
        "version": spec.version,
        "selector": spec.selector,
        "source": spec.source,
        "feature_profile": spec.feature_profile,
        "profile": spec.profile,
        "target": normalized_triplet,
        "host_target": cargo_host_target(),
        "package": spec.package,
        "bins": list(spec.bins),
        "features": list(spec.features),
        "default_features": spec.default_features,
        "source_archive": str(archive_path),
        "source_archive_sha256": _sha256_file(archive_path),
        "source_download_url": release_info.get("download_url"),
        "source_checksum_sha256": release_info.get("checksum"),
        "source_root": str(source_root),
        "manifest_path": str(manifest_path),
        "manifest_sha256": _sha256_file(manifest_path),
        "cargo_lock_present_before_build": had_lockfile,
        "cargo_lock_present_after_build": lock_path.exists(),
        "cargo_lock_sha256": _sha256_file(lock_path) if lock_path.exists() else None,
        "cargo_home": env.get("CARGO_HOME"),
        "cargo_target_dir": env.get("CARGO_TARGET_DIR"),
        "cargo_metadata_root_package_id": package_id,
        "cargo_metadata_workspace_members": cargo_metadata.get("workspace_members"),
        "cargo_metadata": {
            "workspace_root": cargo_metadata.get("workspace_root"),
            "target_directory": cargo_metadata.get("target_directory"),
            "version": cargo_metadata.get("version"),
        },
        "commands": {
            "fetch": fetch_command,
            "build": build_command,
        },
        "reproducibility": {
            "mode": "locked-frozen"
            if had_lockfile
            else "floating-lock-generated-during-build",
            "lockfile_required": had_lockfile,
        },
        "artifacts": artifacts,
        "crate_api": {
            "crate": release_info.get("crate"),
            "version": release_info.get("version"),
        },
    }
    return CargoBuildResult(
        spec=spec,
        project_purl=f"pkg:cargo/{spec.crate}@{spec.version}",
        project_metadata={
            key: value
            for key, value in project_metadata.items()
            if value not in (None, [], {})
        },
        build_metadata=build_metadata,
        artifacts=artifacts,
        source_root=source_root,
        target_dir=target_dir,
        target_triplet=normalized_triplet,
        target_os=target_os,
        target_arch=target_arch,
        build_mode=spec.profile,
        optimization=("release" if spec.profile == "release" else spec.profile),
    )
