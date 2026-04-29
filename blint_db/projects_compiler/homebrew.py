# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import traceback
from pathlib import Path
from sqlite3 import OperationalError

from blint_db import ARCH, HOMEBREW_BUILD_FROM_SOURCE, SYSTEM, logger
from blint_db.handlers.language_handlers.homebrew_handler import (
    ensure_homebrew_formula,
    find_homebrew_artifacts,
    homebrew_cellar,
    homebrew_info,
    homebrew_keg_roots,
    homebrew_prefix,
    homebrew_repository,
)
from blint_db.ingest import ingest_binary_file


def _formula_payload(formula_info: dict) -> dict:
    formulae = formula_info.get("formulae") or []
    if not formulae:
        raise RuntimeError("No Homebrew formula metadata returned")
    return formulae[0]


def _formula_project_purl(formula: dict, version: str | None) -> str:
    package_name = formula.get("name") or formula.get("full_name") or "homebrew-formula"
    normalized_version = version or formula.get("versions", {}).get("stable")
    purl = f"pkg:generic/{package_name}"
    if normalized_version:
        purl += f"@{normalized_version}"
    tap = formula.get("tap") or "homebrew/core"
    return f"{purl}?package_manager=homebrew&tap={tap}"


def _formula_project_metadata(formula: dict) -> dict:
    return {
        "full_name": formula.get("full_name"),
        "tap": formula.get("tap"),
        "desc": formula.get("desc"),
        "homepage": formula.get("homepage"),
        "license": formula.get("license"),
        "versions": formula.get("versions"),
        "dependencies": formula.get("dependencies"),
        "build_dependencies": formula.get("build_dependencies"),
        "test_dependencies": formula.get("test_dependencies"),
        "ruby_source_path": formula.get("ruby_source_path"),
    }


def _matching_installed_entry(formula: dict, keg_root: Path) -> dict | None:
    version_hint = keg_root.name
    for installed_entry in formula.get("installed") or []:
        if installed_entry.get("version") == version_hint:
            return installed_entry
    return None


def add_project_homebrew_db(formula_name, db_file=None, disassemble=False):
    formula_info = ensure_homebrew_formula(formula_name)
    formula = _formula_payload(formula_info)
    project_metadata = _formula_project_metadata(formula)
    keg_roots = homebrew_keg_roots(formula_info)
    all_artifacts: list[str] = []
    if not keg_roots:
        raise RuntimeError(f"No installed Homebrew kegs found for {formula_name}")

    for keg_root in keg_roots:
        installed_entry = _matching_installed_entry(formula, keg_root) or {}
        version = installed_entry.get("version") or formula.get("versions", {}).get(
            "stable"
        )
        project_purl = _formula_project_purl(formula, version)
        artifacts = find_homebrew_artifacts(keg_root)
        all_artifacts.extend(artifacts)
        for artifact in artifacts:
            try:
                ingest_binary_file(
                    artifact,
                    db_file=db_file,
                    project_name=formula.get("full_name")
                    or formula.get("name")
                    or formula_name,
                    project_purl=project_purl,
                    ecosystem="homebrew",
                    project_metadata=project_metadata,
                    build_system="homebrew",
                    target_os=SYSTEM,
                    target_arch=ARCH,
                    target_triplet=f"{ARCH}-{SYSTEM}-homebrew",
                    build_mode=(
                        "source"
                        if not installed_entry.get("poured_from_bottle")
                        else "bottle"
                    ),
                    strip_status="unknown",
                    build_metadata={
                        "formula_name": formula.get("name"),
                        "full_name": formula.get("full_name"),
                        "tap": formula.get("tap"),
                        "installed_entry": installed_entry,
                        "keg_root": str(keg_root),
                        "brew_prefix": homebrew_prefix(),
                        "brew_cellar": homebrew_cellar(formula_name),
                        "brew_repository": homebrew_repository(),
                        "brew_core_repository": homebrew_repository(
                            formula.get("tap") or "homebrew/core"
                        ),
                        "build_from_source_requested": HOMEBREW_BUILD_FROM_SOURCE,
                    },
                    relative_to=keg_root,
                    disassemble=disassemble,
                )
            except (RuntimeError, FileNotFoundError) as exc:
                logger.info(f"error encountered with {formula_name}")
                logger.error(exc)
                logger.error(traceback.format_exc())
    return sorted(dict.fromkeys(all_artifacts))


def mt_homebrew_blint_db_build(formula_name, db_file=None, disassemble=False):
    logger.debug(f"Running Homebrew formula {formula_name}")
    try:
        return add_project_homebrew_db(
            formula_name,
            db_file=db_file,
            disassemble=disassemble,
        )
    except OperationalError as exc:
        logger.info(f"error encountered with {formula_name}")
        logger.error(exc)
        logger.error(traceback.format_exc())
        return []
