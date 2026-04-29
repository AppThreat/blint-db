# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import csv
import json
import os
import shutil
import subprocess
from pathlib import Path

from blint_db import (
    DEBUG_MODE,
    HOMEBREW_BUILD_FROM_SOURCE,
    HOMEBREW_CORE_TAP,
    HOMEBREW_CURATED_FORMULAS_FILE,
    HOMEBREW_EXECUTABLE,
    HOMEBREW_EXTRA_INSTALL_ARGS,
    HOMEBREW_NO_ANALYTICS,
    HOMEBREW_NO_AUTO_UPDATE,
    HOMEBREW_NO_INSTALL_CLEANUP,
    HOMEBREW_REINSTALL_EXISTING,
    logger,
)
from blint_db.handlers.language_handlers import BaseHandler
from blint_db.utils import is_exe

_HOMEBREW_LIBRARY_SUFFIXES = {".a", ".dylib", ".so", ".dll", ".wasm"}
_HOMEBREW_SKIP_DIRS = {
    ".git",
    "include",
    "share",
    "pkgconfig",
    "cmake",
    "man",
    "docs",
    "doc",
    "examples",
    "test",
    "tests",
}


class HomebrewHandler(BaseHandler):
    strip = False

    def build(self, project_name):
        return ensure_homebrew_formula(project_name)

    def find_executables(self, project_name):
        formula_info = homebrew_info(project_name)
        artifacts = []
        for keg_root in homebrew_keg_roots(formula_info):
            artifacts.extend(find_homebrew_artifacts(keg_root))
        return sorted(dict.fromkeys(artifacts))

    def delete_project_files(self, project_name):
        return None

    def get_project_list(self):
        return get_homebrew_projects()


def _homebrew_env() -> dict[str, str]:
    env = os.environ.copy()
    if HOMEBREW_NO_AUTO_UPDATE:
        env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
    if HOMEBREW_NO_INSTALL_CLEANUP:
        env["HOMEBREW_NO_INSTALL_CLEANUP"] = "1"
    if HOMEBREW_NO_ANALYTICS:
        env["HOMEBREW_NO_ANALYTICS"] = "1"
    return env


def _run_brew_command(
    args: list[str], *, capture_output: bool = False, project_name: str = "homebrew"
):
    command = [HOMEBREW_EXECUTABLE, *args]
    result = subprocess.run(
        command,
        env=_homebrew_env(),
        capture_output=capture_output or DEBUG_MODE,
        check=False,
        encoding="utf-8",
    )
    if DEBUG_MODE and result.stderr:
        logger.debug("%s: %s", project_name, result.stderr)
    return result


def _require_homebrew() -> None:
    executable = str(HOMEBREW_EXECUTABLE)
    if not shutil.which(executable) and not Path(executable).exists():
        raise ModuleNotFoundError(
            f"Homebrew executable was not found: {HOMEBREW_EXECUTABLE}"
        )


def homebrew_repository(tap: str | None = None) -> str | None:
    _require_homebrew()
    args = ["--repository"]
    if tap:
        args.append(tap)
    result = _run_brew_command(
        args, capture_output=True, project_name="brew-repository"
    )
    if result.returncode != 0:
        return None
    return (result.stdout or "").strip() or None


def homebrew_prefix(formula_name: str | None = None) -> str | None:
    _require_homebrew()
    args = ["--prefix"]
    if formula_name:
        args.append(formula_name)
    result = _run_brew_command(args, capture_output=True, project_name="brew-prefix")
    if result.returncode != 0:
        return None
    return (result.stdout or "").strip() or None


def homebrew_cellar(formula_name: str | None = None) -> str | None:
    _require_homebrew()
    args = ["--cellar"]
    if formula_name:
        args.append(formula_name)
    result = _run_brew_command(args, capture_output=True, project_name="brew-cellar")
    if result.returncode != 0:
        return None
    return (result.stdout or "").strip() or None


def homebrew_install_command(formula_name: str, *, installed: bool) -> list[str]:
    command = [
        HOMEBREW_EXECUTABLE,
        (
            "reinstall"
            if installed and (HOMEBREW_REINSTALL_EXISTING or HOMEBREW_BUILD_FROM_SOURCE)
            else "install"
        ),
        "--formula",
    ]
    if HOMEBREW_BUILD_FROM_SOURCE:
        command.append("--build-from-source")
    command.extend(HOMEBREW_EXTRA_INSTALL_ARGS)
    command.append(formula_name)
    return command


def load_curated_homebrew_projects(
    file_path: str | os.PathLike | None = None,
) -> list[str]:
    csv_path = Path(file_path or HOMEBREW_CURATED_FORMULAS_FILE)
    if not csv_path.exists():
        return []
    with open(csv_path, "r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return [row["formula"].strip() for row in reader if row.get("formula")]


def get_homebrew_projects() -> list[str]:
    _require_homebrew()
    result = _run_brew_command(
        ["formulae"], capture_output=True, project_name="brew-formulae"
    )
    if result.returncode != 0:
        raise RuntimeError("Unable to list Homebrew formulae")
    return sorted((result.stdout or "").split())


def homebrew_info(formula_name: str) -> dict:
    _require_homebrew()
    result = _run_brew_command(
        ["info", "--json=v2", formula_name],
        capture_output=True,
        project_name=formula_name,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Unable to query Homebrew metadata for {formula_name}")
    return json.loads(result.stdout or "{}")


def _formula_payload(formula_info: dict) -> dict:
    formulae = formula_info.get("formulae") or []
    if not formulae:
        raise RuntimeError("No formula metadata returned from Homebrew")
    return formulae[0]


def ensure_homebrew_formula(formula_name: str) -> dict:
    formula_info = homebrew_info(formula_name)
    formula = _formula_payload(formula_info)
    installed_entries = formula.get("installed") or []
    if (
        installed_entries
        and not HOMEBREW_REINSTALL_EXISTING
        and not HOMEBREW_BUILD_FROM_SOURCE
    ):
        return formula_info

    install_command = homebrew_install_command(
        formula_name,
        installed=bool(installed_entries),
    )
    result = subprocess.run(
        install_command,
        env=_homebrew_env(),
        check=False,
        encoding="utf-8",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE if DEBUG_MODE else subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Homebrew install failed for {formula_name}")
    return homebrew_info(formula_name)


def _keg_path_for_version(formula_name: str, version: str) -> Path | None:
    cellar = homebrew_cellar(formula_name)
    if not cellar:
        return None
    candidate = Path(cellar) / version
    return candidate if candidate.exists() else None


def homebrew_keg_roots(formula_info: dict) -> list[Path]:
    formula = _formula_payload(formula_info)
    formula_name = formula.get("name") or formula.get("full_name")
    roots: list[Path] = []
    for installed_entry in formula.get("installed") or []:
        version = installed_entry.get("version")
        if not version:
            continue
        keg_path = _keg_path_for_version(formula_name, version)
        if keg_path:
            roots.append(keg_path)
    linked_keg = formula.get("linked_keg")
    if linked_keg:
        keg_path = _keg_path_for_version(formula_name, linked_keg)
        if keg_path:
            roots.append(keg_path)
    deduped = []
    seen = set()
    for root in roots:
        resolved = str(root.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(root)
    return deduped


def _should_skip_dir(path_obj: Path) -> bool:
    return any(part.lower() in _HOMEBREW_SKIP_DIRS for part in path_obj.parts)


def _is_homebrew_artifact(path_obj: Path) -> bool:
    if not path_obj.exists() or not path_obj.is_file():
        return False
    if _should_skip_dir(path_obj.parent):
        return False
    if path_obj.suffix.lower() in _HOMEBREW_LIBRARY_SUFFIXES:
        return True
    return is_exe(str(path_obj))


def find_homebrew_artifacts(keg_root: str | os.PathLike) -> list[str]:
    root_path = Path(keg_root)
    if not root_path.exists():
        return []
    preferred_dirs = [
        root_path / "bin",
        root_path / "sbin",
        root_path / "lib",
        root_path / "libexec" / "bin",
        root_path / "libexec" / "lib",
        root_path / "Frameworks",
    ]
    roots_to_scan = [path for path in preferred_dirs if path.exists()]
    if not roots_to_scan:
        roots_to_scan = [root_path]
    selected: dict[str, Path] = {}
    for scan_root in roots_to_scan:
        for path_obj in scan_root.rglob("*"):
            if not _is_homebrew_artifact(path_obj):
                continue
            resolved = str(path_obj.resolve())
            current = selected.get(resolved)
            if current is None or len(str(path_obj.relative_to(root_path))) < len(
                str(current.relative_to(root_path))
            ):
                selected[resolved] = path_obj
    return sorted(str(path) for path in selected.values())
