#!/usr/bin/env python3
"""Build a blint-db corpus from F-Droid APKs.

The apps come from the curated manifest in ``blint_db/inputs/fdroid-apps.csv``
(each row pins a ``package`` and ``version_code``; leave ``version_code``
empty to resolve the current suggested version through the F-Droid API).
Each APK is downloaded from the F-Droid repo, falling back to the archive,
which keeps versions the repo dropped when a newer release came out.

Extraction follows the same ABI model as blint 4's Android reader
(``blint.lib.android_native``): only ``lib/<abi>/`` at the APK root is an
ABI directory, so only those entries are extracted. The ABIs the NDK can
build are selectable with ``--abis``; the retired ones (``armeabi``,
``mips``, ``mips64``) are never extracted. Split bundles and multi-ABI APKs
are one logical app: libraries are deduplicated by sha256 across the whole
run, the same way blint deduplicates them inside one app, so an xapk's
shared copy of a library is ingested once.

Every extracted ``.so`` is ingested as one binary row under a project named
after the app, so the database answers "which app ships this library" with
per-app provenance rather than one anonymous corpus blob.

Usage:
    python scripts/build_fdroid_corpus.py --db-file ./fdroid.db [--disassemble]
    python scripts/build_fdroid_corpus.py --db-file ./fdroid.db --only org.fdroid.fdroid
    python scripts/build_fdroid_corpus.py --list   # resolve URLs only
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from blint_db.config import (
    BLINT_DB_BOOTSTRAP_PATH,
    FDROID_API_URL,
    FDROID_ARCHIVE_URL,
    FDROID_CURATED_APPS_FILE,
    FDROID_HTTP_TIMEOUT,
    FDROID_REPO_URL,
)
from blint_db.ingest import ingest_binary_file
from blint_db.utils.provenance import write_run_metadata

# The ABIs the NDK builds today (blint.lib.android_native.ANDROID_ABIS minus
# riscv64, which F-Droid apps do not ship yet). Retired ABIs are excluded on
# purpose: their presence is a fact blint records, not a corpus target.
SUPPORTED_ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
ABI_TO_ARCH = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}
# Only lib/<abi>/<name>.so at the APK root; AABs nest under <module>/lib/
# and are not APKs, and anything deeper in an APK is not an ABI directory.
LIB_ENTRY_RE = re.compile(r"^lib/(?P<abi>[^/]+)/(?P<name>[^/]+\.so)$")
# Decompression budgets in the shape blint 4 applies to APK members: the
# largest F-Droid app ships well under 1 GiB of native code, so these refuse
# nothing benign while bounding a hostile entry.
MAX_ENTRY_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024


def http_get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "blint-db fdroid corpus"})
    with urllib.request.urlopen(request, timeout=FDROID_HTTP_TIMEOUT) as response:
        return response.read()


def resolve_version_code(package: str) -> int:
    body = http_get(f"{FDROID_API_URL}/packages/{package}")
    return int(json.loads(body)["suggestedVersionCode"])


def apk_urls(package: str, version_code: int) -> list[str]:
    filename = f"{package}_{version_code}.apk"
    return [
        f"{FDROID_REPO_URL}/{filename}",
        f"{FDROID_ARCHIVE_URL}/{filename}",
    ]


def download_apk(urls: list[str], destination: Path) -> str:
    errors = []
    for url in urls:
        try:
            destination.write_bytes(http_get(url))
            return url
        except urllib.error.URLError as exc:
            errors.append(f"{url}: {exc}")
    raise RuntimeError("; ".join(errors))


def read_manifest(manifest_file: Path, only: set[str] | None) -> list[dict]:
    apps = []
    with open(manifest_file, encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            package = (row.get("package") or "").strip()
            if not package or (only and package not in only):
                continue
            apps.append(row)
    return apps


def extract_native_libraries(apk_file: Path, out_dir: Path, abis: set[str]) -> list[tuple[str, str, Path]]:
    """Extract ``lib/<abi>/*.so`` members to ``out_dir``.

    Returns ``(abi, entry name, extracted path)`` triples. Destination names
    are plain basenames, so a crafted member path cannot escape ``out_dir``;
    entries over the per-entry or cumulative budget are refused.
    """
    extracted = []
    total = 0
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(apk_file) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            match = LIB_ENTRY_RE.match(info.filename)
            if not match or match.group("abi") not in abis:
                continue
            if info.file_size > MAX_ENTRY_BYTES:
                raise RuntimeError(f"{info.filename}: entry over budget ({info.file_size} bytes)")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise RuntimeError("apk native payload over cumulative budget")
            abi_dir = out_dir / match.group("abi")
            abi_dir.mkdir(exist_ok=True)
            target = abi_dir / Path(match.group("name")).name
            with archive.open(info) as source, open(target, "wb") as sink:
                sink.write(source.read())
            extracted.append((match.group("abi"), info.filename, target))
    return extracted


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a blint-db corpus from curated F-Droid APKs."
    )
    parser.add_argument("--manifest", type=Path, default=FDROID_CURATED_APPS_FILE)
    parser.add_argument("--db-file", default="blint-v4.db")
    parser.add_argument(
        "--run-metadata-file",
        default=None,
        help="Provenance sidecar to write (defaults to <db-file>.metadata.json).",
    )
    parser.add_argument(
        "--apks-dir",
        type=Path,
        default=BLINT_DB_BOOTSTRAP_PATH / "fdroid-apks",
        help="Directory the APKs are cached in (re-runs skip the download).",
    )
    parser.add_argument(
        "--abis",
        nargs="+",
        default=list(SUPPORTED_ABIS),
        choices=SUPPORTED_ABIS,
    )
    parser.add_argument(
        "--only",
        nargs="+",
        help="Restrict the run to these package ids.",
    )
    parser.add_argument(
        "--disassemble",
        action="store_true",
        help="Collect disassembly fingerprints (needs the extended extra and LLVM).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Resolve and print the download URLs without building anything.",
    )
    args = parser.parse_args()
    abis = set(args.abis)
    only = set(args.only) if args.only else None

    apps = read_manifest(args.manifest, only)
    if not apps:
        print(f"no apps selected from {args.manifest}", file=sys.stderr)
        return 1

    if args.list:
        for row in apps:
            package = row["package"].strip()
            version_code = int(row.get("version_code") or 0) or resolve_version_code(package)
            for url in apk_urls(package, version_code):
                print(url)
        return 0

    args.apks_dir.mkdir(parents=True, exist_ok=True)
    seen_sha256: set[str] = set()
    outcomes = []
    for row in apps:
        package = row["package"].strip()
        pinned = (row.get("version_code") or "").strip()
        version_code = int(pinned) if pinned else resolve_version_code(package)
        version_name = (row.get("version_name") or "").strip() or str(version_code)
        outcome = {
            "selector": f"{package}_{pinned}" if pinned else package,
            "project_name": package,
            "ecosystem": "fdroid",
            "build_system": "gradle",
            "status": "success",
            "unique_libraries": 0,
        }
        outcomes.append(outcome)
        apk_file = args.apks_dir / f"{package}_{version_code}.apk"
        try:
            if apk_file.exists() and apk_file.stat().st_size > 0:
                apk_url = f"cached:{apk_file}"
            else:
                apk_url = download_apk(apk_urls(package, version_code), apk_file)
            libs = extract_native_libraries(
                apk_file, args.apks_dir / "native" / f"{package}_{version_code}", abis
            )
            for abi, entry_name, lib_path in libs:
                digest = sha256_file(lib_path)
                if digest in seen_sha256:
                    continue
                seen_sha256.add(digest)
                ingest_binary_file(
                    str(lib_path),
                    db_file=args.db_file,
                    project_name=package,
                    project_purl=f"pkg:generic/{package}@{version_name}",
                    ecosystem="fdroid",
                    build_system="gradle",
                    target_os="android",
                    target_arch=ABI_TO_ARCH[abi],
                    build_metadata={
                        "source": "f-droid",
                        "url": apk_url,
                        "version_code": version_code,
                        "version_name": version_name,
                        "abi": abi,
                        "apk_entry": entry_name,
                    },
                    disassemble=args.disassemble,
                )
                outcome["unique_libraries"] += 1
            print(
                f"{package} {version_name} ({version_code}): "
                f"{outcome['unique_libraries']} unique libraries ingested"
            )
        except Exception as exc:  # noqa: BLE001 - one app failing must not stop the corpus
            outcome["status"] = "failure"
            outcome["failure"] = {"message": str(exc)}
            print(f"!! {package} {version_code}: {exc}", file=sys.stderr)
    write_run_metadata(
        command="build-fdroid",
        db_file=args.db_file,
        metadata_file=args.run_metadata_file,
        disassemble=args.disassemble,
        selected_projects=[row["package"].strip() for row in apps],
        project_outcomes=outcomes,
    )
    failures = [o for o in outcomes if o["status"] != "success"]
    if failures:
        print(
            f"{len(failures)} app(s) failed; a curated pin that 404s is stale "
            "and needs a new version_code in the manifest",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
