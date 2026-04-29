from __future__ import annotations

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, distribution, version
from pathlib import Path
from typing import Any, Sequence

from blint_db import (
    BLINT_DB_SCHEMA_FAMILY,
    BLINT_DB_SCHEMA_VERSION,
    BUILD_JOBS,
    CARGO_CURATED_CRATES_FILE,
    CARGO_DEFAULT_PROFILE,
    CARGO_DEFAULT_TARGET,
    CARGO_EXECUTABLE,
    CARGO_REGISTRY_API,
    CONAN_CURATED_PACKAGES_FILE,
    CONAN_DEFAULT_BUILD_PROFILE,
    CONAN_DEFAULT_BUILD_TYPE,
    CONAN_DEFAULT_DEPLOYER,
    CONAN_DEFAULT_HOST_PROFILE,
    CONAN_EXECUTABLE,
    CONAN_REMOTE,
    CONAN_REMOTE_URL,
    HOMEBREW_BUILD_FROM_SOURCE,
    HOMEBREW_CORE_TAP,
    HOMEBREW_CURATED_FORMULAS_FILE,
    HOMEBREW_EXECUTABLE,
    MESON_BUILD_TYPE,
    MESON_DEFAULT_LIBRARY,
    MESON_STRIP,
    VCPKG_COMMIT_HASH,
    VCPKG_DEFAULT_TRIPLET,
    VCPKG_KEEP_GOING,
    VCPKG_LOCATION,
    VCPKG_URL,
    WRAPDB_COMMIT_HASH,
    WRAPDB_LOCATION,
    WRAPDB_URL,
)
from blint_db.handlers.sqlite_handler import execute_statement
from blint_db.utils.json import dump_json_file

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_run_metadata_path(db_file: str | os.PathLike) -> Path:
    db_path = Path(db_file)
    if db_path.suffix:
        return db_path.with_suffix(".metadata.json")
    return db_path.with_name(f"{db_path.name}.metadata.json")


def _safe_command_output(
    command: Sequence[str], *, cwd: str | os.PathLike | None = None
) -> str | None:
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            capture_output=True,
            check=False,
            encoding="utf-8",
        )
    except (FileNotFoundError, OSError):
        return None
    output = (completed.stdout or completed.stderr or "").strip()
    if not output:
        return None
    return output.splitlines()[0].strip()


def _package_metadata(package_name: str) -> dict[str, Any] | None:
    try:
        dist = distribution(package_name)
    except PackageNotFoundError:
        return None
    metadata: dict[str, Any] = {"version": version(package_name)}
    direct_url_text = dist.read_text("direct_url.json")
    if direct_url_text:
        try:
            metadata["direct_url"] = json.loads(direct_url_text)
        except json.JSONDecodeError:
            metadata["direct_url"] = direct_url_text
    return metadata


def _git_repo_metadata(
    path: str | os.PathLike | None, *, expected_commit: str | None = None
) -> dict[str, Any] | None:
    if not path:
        return None
    repo_path = Path(path)
    if not repo_path.exists() or not (repo_path / ".git").exists():
        return None
    commit = _safe_command_output(["git", "rev-parse", "HEAD"], cwd=repo_path)
    branch = _safe_command_output(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_path
    )
    dirty_output = _safe_command_output(["git", "status", "--short"], cwd=repo_path)
    metadata = {
        "path": str(repo_path),
        "commit": commit,
        "branch": branch,
        "dirty": bool(dirty_output),
    }
    if expected_commit:
        metadata["expected_commit"] = expected_commit
        metadata["matches_expected_commit"] = (
            commit == expected_commit if commit else None
        )
    return metadata


def _tool_versions() -> dict[str, str]:
    tools = {
        "python": sys.version.split()[0],
        "brew": _safe_command_output([HOMEBREW_EXECUTABLE, "--version"]),
        "uv": _safe_command_output(["uv", "--version"]),
        "meson": _safe_command_output(["meson", "--version"]),
        "ninja": _safe_command_output(["ninja", "--version"]),
        "cmake": _safe_command_output(["cmake", "--version"]),
        "conan": _safe_command_output([CONAN_EXECUTABLE, "--version"]),
        "cargo": _safe_command_output(["cargo", "--version"]),
        "rustc": _safe_command_output(["rustc", "--version"]),
        "swift": _safe_command_output(["swift", "--version"]),
        "llvm-config": _safe_command_output(["llvm-config", "--version"]),
    }
    return {key: value for key, value in tools.items() if value}


def _homebrew_repository_path(tap: str | None = None) -> str | None:
    args = [HOMEBREW_EXECUTABLE, "--repository"]
    if tap:
        args.append(tap)
    return _safe_command_output(args)


def _homebrew_prefix(command_flag: str) -> str | None:
    return _safe_command_output([HOMEBREW_EXECUTABLE, command_flag])


def _homebrew_formula_summary(formula_name: str) -> dict[str, Any] | None:
    try:
        completed = subprocess.run(
            [HOMEBREW_EXECUTABLE, "info", "--json=v2", formula_name],
            capture_output=True,
            check=False,
            encoding="utf-8",
        )
    except (FileNotFoundError, OSError):
        return None
    if completed.returncode != 0 or not completed.stdout:
        return None
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    formulae = payload.get("formulae") or []
    if not formulae:
        return None
    formula = formulae[0]
    return {
        "name": formula.get("name"),
        "full_name": formula.get("full_name"),
        "tap": formula.get("tap"),
        "tap_git_head": formula.get("tap_git_head"),
        "versions": formula.get("versions"),
        "linked_keg": formula.get("linked_keg"),
        "installed_versions": [
            entry.get("version")
            for entry in (formula.get("installed") or [])
            if entry.get("version")
        ],
        "ruby_source_path": formula.get("ruby_source_path"),
    }


def _db_table_counts(db_file: str | os.PathLike) -> dict[str, int]:
    rows = execute_statement(
        """
        SELECT 'Projects' AS table_name, COUNT(*) AS count FROM Projects
        UNION ALL SELECT 'Builds', COUNT(*) FROM Builds
        UNION ALL SELECT 'Binaries', COUNT(*) FROM Binaries
        UNION ALL SELECT 'Symbols', COUNT(*) FROM Symbols
        UNION ALL SELECT 'Dependencies', COUNT(*) FROM Dependencies
        UNION ALL SELECT 'FunctionFingerprints', COUNT(*) FROM FunctionFingerprints
        """,
        db_file=str(db_file),
    )
    return {str(row["table_name"]): int(row["count"]) for row in rows}


def build_run_metadata(
    *,
    command: str,
    db_file: str | os.PathLike,
    metadata_file: str | os.PathLike,
    disassemble: bool = False,
    test_mode: bool = False,
    selected_projects: Sequence[str] | None = None,
) -> dict[str, Any]:
    db_path = Path(db_file)
    metadata_path = Path(metadata_file)
    return {
        "generated_at": _utc_now(),
        "schema": {
            "family": BLINT_DB_SCHEMA_FAMILY,
            "version": BLINT_DB_SCHEMA_VERSION,
        },
        "run": {
            "command": command,
            "argv": sys.argv,
            "working_directory": os.getcwd(),
            "db_file": str(db_path),
            "metadata_file": str(metadata_path),
            "disassemble": disassemble,
            "test_mode": test_mode,
            "selected_projects": list(selected_projects or []),
        },
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "platform": platform.platform(),
        },
        "runner": {
            "github_workflow": os.getenv("GITHUB_WORKFLOW"),
            "github_run_id": os.getenv("GITHUB_RUN_ID"),
            "github_run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
            "github_sha": os.getenv("GITHUB_SHA"),
            "runner_os": os.getenv("RUNNER_OS"),
            "runner_arch": os.getenv("RUNNER_ARCH"),
        },
        "config": {
            "build_jobs": BUILD_JOBS,
            "cargo_curated_crates_file": str(CARGO_CURATED_CRATES_FILE),
            "cargo_default_profile": CARGO_DEFAULT_PROFILE,
            "cargo_default_target": CARGO_DEFAULT_TARGET,
            "conan_curated_packages_file": str(CONAN_CURATED_PACKAGES_FILE),
            "conan_default_build_type": CONAN_DEFAULT_BUILD_TYPE,
            "conan_default_deployer": CONAN_DEFAULT_DEPLOYER,
            "conan_default_host_profile": CONAN_DEFAULT_HOST_PROFILE,
            "conan_default_build_profile": CONAN_DEFAULT_BUILD_PROFILE,
            "conan_remote": CONAN_REMOTE,
            "homebrew_build_from_source": HOMEBREW_BUILD_FROM_SOURCE,
            "homebrew_curated_formulas_file": str(HOMEBREW_CURATED_FORMULAS_FILE),
            "meson_build_type": MESON_BUILD_TYPE,
            "meson_default_library": MESON_DEFAULT_LIBRARY,
            "meson_strip": MESON_STRIP,
            "vcpkg_default_triplet": VCPKG_DEFAULT_TRIPLET,
            "vcpkg_keep_going": VCPKG_KEEP_GOING,
        },
        "tool_versions": _tool_versions(),
        "packages": {
            package_name: package_metadata
            for package_name in ("blint-db", "blint", "nyxstone")
            if (package_metadata := _package_metadata(package_name))
        },
        "repositories": {
            repo_name: repo_metadata
            for repo_name, repo_metadata in {
                "blint-db": _git_repo_metadata(_REPO_ROOT),
                "wrapdb": _git_repo_metadata(
                    WRAPDB_LOCATION,
                    expected_commit=WRAPDB_COMMIT_HASH,
                )
                if command == "build-meson"
                else None,
                "vcpkg": _git_repo_metadata(
                    VCPKG_LOCATION,
                    expected_commit=VCPKG_COMMIT_HASH,
                )
                if command == "build-vcpkg"
                else None,
                "homebrew-brew": _git_repo_metadata(_homebrew_repository_path())
                if command == "build-homebrew"
                else None,
                "homebrew-core": _git_repo_metadata(
                    _homebrew_repository_path(HOMEBREW_CORE_TAP)
                )
                if command == "build-homebrew"
                else None,
            }.items()
            if repo_metadata
        },
        "ecosystem_sources": {
            "wrapdb": {
                "url": WRAPDB_URL,
                "expected_commit": WRAPDB_COMMIT_HASH,
                "path": str(WRAPDB_LOCATION),
            }
            if command == "build-meson"
            else None,
            "vcpkg": {
                "url": VCPKG_URL,
                "expected_commit": VCPKG_COMMIT_HASH,
                "triplet": VCPKG_DEFAULT_TRIPLET,
                "path": str(VCPKG_LOCATION),
            }
            if command == "build-vcpkg"
            else None,
            "homebrew": {
                "executable": HOMEBREW_EXECUTABLE,
                "core_tap": HOMEBREW_CORE_TAP,
                "build_from_source": HOMEBREW_BUILD_FROM_SOURCE,
                "curated_formulas_file": str(HOMEBREW_CURATED_FORMULAS_FILE),
                "repository": _homebrew_repository_path(),
                "core_repository": _homebrew_repository_path(HOMEBREW_CORE_TAP),
                "prefix": _homebrew_prefix("--prefix"),
                "cellar": _homebrew_prefix("--cellar"),
                "selected_formulae": [
                    summary
                    for formula_name in (selected_projects or [])
                    if (summary := _homebrew_formula_summary(formula_name))
                ],
            }
            if command == "build-homebrew"
            else None,
            "cargo": {
                "executable": CARGO_EXECUTABLE,
                "registry_api": CARGO_REGISTRY_API,
                "curated_crates_file": str(CARGO_CURATED_CRATES_FILE),
                "default_profile": CARGO_DEFAULT_PROFILE,
                "default_target": CARGO_DEFAULT_TARGET,
                "selected_crates": list(selected_projects or []),
            }
            if command == "build-cargo"
            else None,
            "conan": {
                "executable": CONAN_EXECUTABLE,
                "remote": CONAN_REMOTE,
                "remote_url": CONAN_REMOTE_URL,
                "curated_packages_file": str(CONAN_CURATED_PACKAGES_FILE),
                "default_build_type": CONAN_DEFAULT_BUILD_TYPE,
                "default_deployer": CONAN_DEFAULT_DEPLOYER,
                "host_profile": CONAN_DEFAULT_HOST_PROFILE,
                "build_profile": CONAN_DEFAULT_BUILD_PROFILE,
                "selected_packages": list(selected_projects or []),
            }
            if command == "build-conan"
            else None,
        },
        "database": {
            "path": str(db_path),
            "size_bytes": db_path.stat().st_size if db_path.exists() else 0,
            "table_counts": _db_table_counts(db_path),
        },
    }


def write_run_metadata(
    *,
    command: str,
    db_file: str | os.PathLike,
    metadata_file: str | os.PathLike | None = None,
    disassemble: bool = False,
    test_mode: bool = False,
    selected_projects: Sequence[str] | None = None,
) -> Path:
    target_path = (
        Path(metadata_file) if metadata_file else default_run_metadata_path(db_file)
    )
    target_path.parent.mkdir(parents=True, exist_ok=True)
    dump_json_file(
        target_path,
        build_run_metadata(
            command=command,
            db_file=db_file,
            metadata_file=target_path,
            disassemble=disassemble,
            test_mode=test_mode,
            selected_projects=selected_projects,
        ),
    )
    return target_path
