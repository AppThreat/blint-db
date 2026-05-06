from __future__ import annotations

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import csv
import json
import subprocess
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

_HOME_BREW_ANALYTICS_URL = (
    "https://formulae.brew.sh/api/analytics/install-on-request/365d.json"
)
_HOME_BREW_FORMULA_API = "https://formulae.brew.sh/api/formula/{formula}.json"
_CRATES_IO_CRATES_API = "https://crates.io/api/v1/crates"
_DEFAULT_TIMEOUT = 60
_DEFAULT_USER_AGENT = "blint-db-manifest-generator/2.0"

DEFAULT_CONAN_RANKED_REFERENCES = [
    "zlib/1.3.1",
    "openssl/3.5.0",
    "fmt/11.2.0",
    "protobuf/5.29.3",
    "spdlog/1.15.3",
    "libpng/1.6.47",
    "libjpeg-turbo/3.1.0",
    "zstd/1.5.7",
    "bzip2/1.0.8",
    "libarchive/3.8.1",
    "libxml2/2.14.4",
    "libcurl/8.14.1",
    "c-ares/1.34.5",
    "libuv/1.51.0",
    "freetype/2.13.3",
    "capstone/5.0.6",
    "re2/20240702",
    "poco/1.14.2",
    "boost/1.86.0",
    "abseil/20240116.2",
    "onetbb/2022.0.0",
    "nlohmann_json/3.11.3",
    "sqlite3/3.48.0",
    "libevent/2.1.12",
    "xxhash/0.8.3",
]


def _fetch_json(url: str, *, timeout: int = _DEFAULT_TIMEOUT) -> dict[str, Any]:
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": _DEFAULT_USER_AGENT,
        },
    )
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def write_csv_manifest(
    output_file: str | Path,
    *,
    fieldnames: list[str],
    rows: Iterable[dict[str, Any]],
) -> Path:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})
    return output_path


def _homebrew_language_family(
    formula_name: str, formula_payload: dict[str, Any]
) -> tuple[str, str]:
    lowered_name = formula_name.lower()
    desc = str(formula_payload.get("desc") or "").lower()
    homepage = str(formula_payload.get("homepage") or "").lower()
    deps = {
        part.lower()
        for part in (formula_payload.get("dependencies") or [])
        + (formula_payload.get("build_dependencies") or [])
    }
    if "rust" in deps or any(token in desc for token in ("rust", "cargo")):
        return "rust", "cargo"
    if "go" in deps or homepage.startswith("https://go.") or "golang" in desc:
        return "go", "go"
    if "swift" in deps or "swift" in desc or "swift" in homepage:
        return "swift", "swiftpm"
    if any(token in lowered_name for token in ("cpp", "cxx")) or "c++" in desc:
        return "c++", "c++"
    return "c", "c"


def fetch_homebrew_top_formulae(limit: int) -> list[str]:
    payload = _fetch_json(_HOME_BREW_ANALYTICS_URL)
    formulae = payload.get("formulae") or payload.get("items") or []
    return [entry.get("formula") for entry in formulae[:limit] if entry.get("formula")]


def fetch_homebrew_formula_metadata(formula_name: str) -> dict[str, Any]:
    return _fetch_json(
        _HOME_BREW_FORMULA_API.format(formula=quote(formula_name, safe=""))
    )


def build_homebrew_manifest_rows(
    formula_names: Iterable[str],
    *,
    limit: int,
    metadata_loader=None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    metadata_loader = metadata_loader or fetch_homebrew_formula_metadata
    for rank, formula_name in enumerate(formula_names, start=1):
        if len(rows) >= limit:
            break
        try:
            formula_payload = metadata_loader(formula_name) or {}
        except Exception:  # pragma: no cover - network-dependent resilience path
            formula_payload = {}
        language_family, ecosystem = _homebrew_language_family(
            formula_name, formula_payload
        )
        rows.append(
            {
                "formula": formula_name,
                "language_family": language_family,
                "upstream_ecosystem": ecosystem,
                "reason": f"top_installs_rank_{rank}",
                "notes": formula_payload.get("desc") or "",
            }
        )
    return rows


def generate_homebrew_manifest(
    *,
    limit: int,
    output_file: str | Path,
    formula_names: Iterable[str] | None = None,
) -> Path:
    selected_formulae = list(formula_names or fetch_homebrew_top_formulae(limit))
    rows = build_homebrew_manifest_rows(selected_formulae, limit=limit)
    return write_csv_manifest(
        output_file,
        fieldnames=[
            "formula",
            "language_family",
            "upstream_ecosystem",
            "reason",
            "notes",
        ],
        rows=rows,
    )


def fetch_cargo_crates_page(
    *,
    limit: int,
    page: int = 1,
    query: str | None = None,
    category: str | None = None,
) -> dict[str, Any]:
    params = {
        "page": page,
        "per_page": limit,
        "sort": "downloads",
    }
    if query:
        params["q"] = query
    if category:
        params["category"] = category
    return _fetch_json(f"{_CRATES_IO_CRATES_API}?{urlencode(params)}")


def build_cargo_manifest_rows(
    crates_payload: dict[str, Any],
    *,
    limit: int,
    include_dev_profile: bool = False,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for crate in (crates_payload.get("crates") or [])[:limit]:
        crate_name = crate.get("id") or crate.get("name")
        version = crate.get("max_version") or crate.get("newest_version")
        if not crate_name or not version:
            continue
        rows.append(
            {
                "crate": crate_name,
                "version": version,
                "feature_profile": "default",
                "profile": "release",
                "default_features": "true",
                "features": "",
                "bins": "",
                "package": crate_name,
                "target": "",
            }
        )
        if include_dev_profile:
            rows.append(
                {
                    "crate": crate_name,
                    "version": version,
                    "feature_profile": "debug",
                    "profile": "dev",
                    "default_features": "true",
                    "features": "",
                    "bins": "",
                    "package": crate_name,
                    "target": "",
                }
            )
    return rows


def generate_cargo_manifest(
    *,
    limit: int,
    output_file: str | Path,
    query: str | None = None,
    category: str | None = None,
    include_dev_profile: bool = False,
) -> Path:
    payload = fetch_cargo_crates_page(
        limit=limit,
        query=query,
        category=category,
    )
    rows = build_cargo_manifest_rows(
        payload,
        limit=limit,
        include_dev_profile=include_dev_profile,
    )
    return write_csv_manifest(
        output_file,
        fieldnames=[
            "crate",
            "version",
            "feature_profile",
            "profile",
            "default_features",
            "features",
            "bins",
            "package",
            "target",
        ],
        rows=rows,
    )


def resolve_conan_reference_versions(
    package_names: Iterable[str],
    *,
    remote: str = "conancenter",
    conan_executable: str = "conan",
) -> list[str]:
    references: list[str] = []
    for package_name in package_names:
        pattern = package_name if "/" in package_name else f"{package_name}/*"
        completed = subprocess.run(
            [conan_executable, "search", pattern, "-r", remote, "--format=json"],
            capture_output=True,
            check=False,
            encoding="utf-8",
        )
        if completed.returncode != 0:
            continue
        try:
            payload = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError:
            continue
        results = payload.get("results") or []
        for result in results:
            items = result.get("items") or []
            for item in items:
                reference = item.get("reference") or item.get("recipe")
                if reference:
                    references.append(reference)
                    break
            if references and references[-1].startswith(
                package_name.split("/")[0] + "/"
            ):
                break
    return references


def build_conan_manifest_rows(
    references: Iterable[str],
    *,
    limit: int,
    include_static_debug: bool = True,
    include_shared_release: bool = True,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for reference in references:
        if len({row["reference"] for row in rows}) >= limit:
            break
        if include_shared_release and (reference, "shared-release") not in seen:
            rows.append(
                {
                    "reference": reference,
                    "configuration": "shared-release",
                    "settings": "",
                    "options": "*:shared=True",
                    "conf": "",
                    "package_type": "library",
                    "shared": "True",
                    "build_type": "Release",
                    "target_os": "",
                    "target_arch": "",
                    "artifact_roots": "lib;bin",
                    "notes": "Generated from ranked Conan package list (shared release)",
                }
            )
            seen.add((reference, "shared-release"))
        if include_static_debug and (reference, "static-debug") not in seen:
            rows.append(
                {
                    "reference": reference,
                    "configuration": "static-debug",
                    "settings": "",
                    "options": "*:shared=False",
                    "conf": "",
                    "package_type": "library",
                    "shared": "False",
                    "build_type": "Debug",
                    "target_os": "",
                    "target_arch": "",
                    "artifact_roots": "lib;bin",
                    "notes": "Generated from ranked Conan package list (static debug)",
                }
            )
            seen.add((reference, "static-debug"))
    return rows


def generate_conan_manifest(
    *,
    limit: int,
    output_file: str | Path,
    references: Iterable[str] | None = None,
    remote: str = "conancenter",
    conan_executable: str = "conan",
    resolve_with_conan: bool = False,
    include_static_debug: bool = True,
    include_shared_release: bool = True,
) -> Path:
    selected_references = list(references or DEFAULT_CONAN_RANKED_REFERENCES[:limit])
    if resolve_with_conan and selected_references:
        selected_references = (
            resolve_conan_reference_versions(
                selected_references,
                remote=remote,
                conan_executable=conan_executable,
            )
            or selected_references
        )
    rows = build_conan_manifest_rows(
        selected_references,
        limit=limit,
        include_static_debug=include_static_debug,
        include_shared_release=include_shared_release,
    )
    return write_csv_manifest(
        output_file,
        fieldnames=[
            "reference",
            "configuration",
            "settings",
            "options",
            "conf",
            "package_type",
            "shared",
            "build_type",
            "target_os",
            "target_arch",
            "artifact_roots",
            "notes",
        ],
        rows=rows,
    )
