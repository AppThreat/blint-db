# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import List

from blint_db import (
    BLINT_DB_FILE,
    CARGO_CURATED_CRATES_FILE,
    CARGO_FEW_PACKAGES,
    CONAN_CURATED_PACKAGES_FILE,
    CONAN_FEW_PACKAGES,
    HOMEBREW_CURATED_FORMULAS_FILE,
    VCPKG_LOCATION,
)
from blint_db.handlers.language_handlers.cargo_handler import (
    get_cargo_projects,
    load_curated_cargo_projects,
    resolve_cargo_project_spec,
)
from blint_db.handlers.language_handlers.conan_handler import (
    load_curated_conan_projects,
    resolve_conan_project_spec,
)
from blint_db.handlers.language_handlers.homebrew_handler import (
    get_homebrew_projects,
    load_curated_homebrew_projects,
)
from blint_db.handlers.language_handlers.vcpkg_handler import (
    get_vcpkg_projects,
    remove_vcpkg_project,
)
from blint_db.handlers.language_handlers.wrapdb_handler import (
    get_wrapdb_projects,
    remove_wrapdb_project,
)
from blint_db.handlers.sqlite_handler import clear_sqlite_database, create_database
from blint_db.ingest import infer_project_name, ingest_binary_file, ingest_metadata_file
from blint_db.projects_compiler.cargo import mt_cargo_blint_db_build
from blint_db.projects_compiler.conan import mt_conan_blint_db_build
from blint_db.projects_compiler.homebrew import mt_homebrew_blint_db_build
from blint_db.projects_compiler.meson import mt_meson_blint_db_build
from blint_db.projects_compiler.vcpkg import mt_vcpkg_blint_db_build
from blint_db.utils.provenance import write_run_metadata


def build_parser():
    parser = argparse.ArgumentParser(
        prog="blint-db",
        description="Build and ingest blint v3 metadata into the blint-db v2 SQLite schema.",
    )
    parser.add_argument(
        "--db-file",
        dest="db_file",
        default=BLINT_DB_FILE,
        help="SQLite database file to create or update. Defaults to blint.db.",
    )
    parser.add_argument(
        "--run-metadata-file",
        dest="run_metadata_file",
        help="Optional JSON sidecar file capturing provenance for a build run.",
    )
    parser.add_argument(
        "--clean-start",
        dest="clean",
        action="store_true",
        help="Remove the existing database before running the selected command.",
    )
    parser.add_argument(
        "--disassemble",
        dest="disassemble",
        action="store_true",
        help="Collect disassembly hashes and function fingerprints when nyxstone support is installed.",
    )
    parser.add_argument(
        "-f",
        "--few-packages",
        dest="test_mode",
        action="store_true",
        help="Build a smaller package subset for debugging workflows.",
    )
    parser.add_argument(
        "-s",
        "--select-project",
        nargs="+",
        dest="sel_project",
        help="Specific project(s) to build when using Meson or vcpkg workflows.",
    )
    parser.add_argument(
        "-Z1",
        "--meson-blintdb",
        dest="meson",
        action="store_true",
        help="Legacy alias for the build-meson command.",
    )
    parser.add_argument(
        "-Z2",
        "--vcpkg-blintdb",
        dest="vcpkg",
        action="store_true",
        help="Legacy alias for the build-vcpkg command.",
    )

    subparsers = parser.add_subparsers(dest="command")

    ingest_parser = subparsers.add_parser(
        "ingest",
        help="Ingest one binary or one pre-generated blint metadata JSON document.",
    )
    ingest_parser.add_argument(
        "-i",
        "--input",
        dest="input",
        help="Binary file to analyze with blint before ingestion.",
    )
    ingest_parser.add_argument(
        "--metadata-file",
        dest="metadata_file",
        help="Path to a pre-generated blint metadata JSON file to ingest.",
    )
    ingest_parser.add_argument(
        "--project-name",
        dest="project_name",
        help="Project name. Defaults to the input filename stem.",
    )
    ingest_parser.add_argument("--project-purl", dest="project_purl")
    ingest_parser.add_argument("--ecosystem", dest="ecosystem", default="manual")
    ingest_parser.add_argument("--build-system", dest="build_system", default="manual")
    ingest_parser.add_argument("--target-os", dest="target_os")
    ingest_parser.add_argument("--target-arch", dest="target_arch")
    ingest_parser.add_argument("--target-triplet", dest="target_triplet")
    ingest_parser.add_argument("--build-mode", dest="build_mode", default="manual")
    ingest_parser.add_argument("--optimization", dest="optimization")
    ingest_parser.add_argument(
        "--strip-status",
        dest="strip_status",
        choices=["unknown", "stripped", "unstripped"],
        default="unknown",
    )
    ingest_parser.add_argument(
        "--project-metadata-file",
        dest="project_metadata_file",
        help="Optional JSON file with project metadata to store alongside the project record.",
    )
    ingest_parser.add_argument(
        "--source-sbom-file",
        dest="source_sbom_file",
        help="Optional source SBOM JSON file to store with the project record.",
    )
    ingest_parser.add_argument(
        "--build-metadata-json",
        dest="build_metadata_json",
        help="Optional JSON object string with build metadata for the Builds table.",
    )
    ingest_parser.add_argument(
        "--relative-to",
        dest="relative_to",
        help="Path prefix used to normalize stored binary relative paths.",
    )

    def _add_build_selection_arguments(subparser):
        subparser.add_argument(
            "-f",
            "--few-packages",
            dest="test_mode",
            action="store_true",
            default=argparse.SUPPRESS,
            help="Build a smaller package subset for debugging workflows.",
        )
        subparser.add_argument(
            "-s",
            "--select-project",
            nargs="+",
            dest="sel_project",
            default=argparse.SUPPRESS,
            help="Specific project(s) to build for this workflow.",
        )

    build_meson_parser = subparsers.add_parser(
        "build-meson",
        help="Build wrapdb/Meson projects and ingest the resulting binaries.",
    )
    _add_build_selection_arguments(build_meson_parser)
    build_meson_parser.add_argument(
        "--remove-after-build",
        dest="remove_after_build",
        action="store_true",
        default=True,
        help=argparse.SUPPRESS,
    )

    build_vcpkg_parser = subparsers.add_parser(
        "build-vcpkg",
        help="Build vcpkg projects and ingest the resulting binaries.",
    )
    _add_build_selection_arguments(build_vcpkg_parser)
    build_vcpkg_parser.add_argument(
        "--remove-after-build",
        dest="remove_after_build",
        action="store_true",
        default=True,
        help=argparse.SUPPRESS,
    )

    build_homebrew_parser = subparsers.add_parser(
        "build-homebrew",
        help="Install Homebrew formulas and ingest the resulting binaries.",
    )
    _add_build_selection_arguments(build_homebrew_parser)
    build_homebrew_parser.add_argument(
        "--remove-after-build",
        dest="remove_after_build",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,
    )

    build_cargo_parser = subparsers.add_parser(
        "build-cargo",
        help="Build crates.io Rust binaries and ingest the resulting artifacts.",
    )
    _add_build_selection_arguments(build_cargo_parser)
    build_cargo_parser.add_argument(
        "--remove-after-build",
        dest="remove_after_build",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,
    )

    build_conan_parser = subparsers.add_parser(
        "build-conan",
        help="Build curated Conan Center packages and ingest the resulting C/C++ binaries.",
    )
    _add_build_selection_arguments(build_conan_parser)
    build_conan_parser.add_argument(
        "--remove-after-build",
        dest="remove_after_build",
        action="store_true",
        default=False,
        help=argparse.SUPPRESS,
    )
    return parser


def arguments_parser():
    return build_parser().parse_args()


def _parse_json_argument(raw_json: str | None):
    if not raw_json:
        return None
    return json.loads(raw_json)


def _resolve_command(args) -> str | None:
    if args.command:
        return args.command
    if args.meson:
        return "build-meson"
    if args.vcpkg:
        return "build-vcpkg"
    if getattr(args, "input", None) or getattr(args, "metadata_file", None):
        return "ingest"
    return None


def _resolve_selected_wrapdb_projects(projects_list, selected_projects):
    if not selected_projects:
        return projects_list
    project_map = {name: wrap_file for name, wrap_file in projects_list}
    missing = [name for name in selected_projects if name not in project_map]
    if missing:
        raise SystemExit(
            "Unknown wrapdb project(s): "
            f"{', '.join(missing)}. Use one of: {', '.join(sorted(project_map)[:20])}"
        )
    return [(name, project_map[name]) for name in selected_projects]


def _resolve_selected_vcpkg_projects(projects_list, selected_projects):
    if not selected_projects:
        return projects_list
    project_set = set(projects_list)
    missing = [name for name in selected_projects if name not in project_set]
    if missing:
        raise SystemExit(
            "Unknown vcpkg project(s): "
            f"{', '.join(missing)}. Use one of: {', '.join(sorted(project_set)[:20])}"
        )
    return list(selected_projects)


def _resolve_selected_homebrew_projects(projects_list, selected_projects):
    if not selected_projects:
        return projects_list
    project_set = set(projects_list)
    missing = [name for name in selected_projects if name not in project_set]
    if missing:
        raise SystemExit(
            "Unknown Homebrew formula(s): "
            f"{', '.join(missing)}. Use one of: {', '.join(sorted(project_set)[:20])}"
        )
    return list(selected_projects)


def _resolve_selected_cargo_projects(projects_list, selected_projects):
    if not selected_projects:
        return projects_list
    resolved_projects = []
    missing = []
    for selector in selected_projects:
        try:
            resolved_projects.append(
                resolve_cargo_project_spec(selector, curated_projects=projects_list)
            )
        except ValueError:
            missing.append(selector)
    if missing:
        available = ", ".join(project.selector for project in projects_list[:20])
        raise SystemExit(
            "Unknown cargo crate(s): "
            f"{', '.join(missing)}. Use crate@version or one of: {available}"
        )
    return resolved_projects


def _resolve_selected_conan_projects(projects_list, selected_projects):
    if not selected_projects:
        return projects_list
    resolved_projects = []
    missing = []
    for selector in selected_projects:
        try:
            resolved_projects.append(
                resolve_conan_project_spec(selector, curated_projects=projects_list)
            )
        except ValueError:
            missing.append(selector)
    if missing:
        available = ", ".join(project.selector for project in projects_list[:20])
        raise SystemExit(
            "Unknown Conan package(s): "
            f"{', '.join(missing)}. Use name/version[#configuration] or one of: {available}"
        )
    return resolved_projects


def _require_curated_projects(projects_list, *, ecosystem: str, curated_file: Path):
    if projects_list:
        return projects_list
    raise SystemExit(
        f"The curated {ecosystem} input file '{curated_file}' is missing or has no valid entries. "
        f"Update it or override it with the matching BLINT_DB_* env var."
    )


def meson_add_blint_bom_process(
    *,
    db_file: str,
    disassemble: bool = False,
    test_mode: bool = False,
    sel_project: List | None = None,
):
    projects_list = get_wrapdb_projects()
    projects_list = _resolve_selected_wrapdb_projects(projects_list, sel_project)
    if test_mode:
        projects_list = projects_list[:10]
    for project_name_tuple in projects_list:
        executables = mt_meson_blint_db_build(
            project_name_tuple,
            db_file=db_file,
            disassemble=disassemble,
        )
        print(
            f"Build complete for {project_name_tuple[0]}. Got {len(executables)} binaries."
        )
        remove_wrapdb_project(project_name_tuple[0])


def remove_temp_ar():
    """
    Removes `ar-temp-########` files created by blint extract-ar function,
    after we have completed our tasks.
    """
    try:
        for dirname in Path(tempfile.gettempdir()).glob("ar-temp-*"):
            try:
                shutil.rmtree(dirname, ignore_errors=True)
            except OSError as exc:
                print(f"Error deleting file {dirname}: {exc}")
    except Exception as exc:  # pragma: no cover - defensive cleanup path
        print(f"Error during cleanup: {exc}")


def vcpkg_add_blint_bom_process(
    *,
    db_file: str,
    disassemble: bool = False,
    test_mode: bool = False,
    sel_project: List | None = None,
):
    projects_list = get_vcpkg_projects()
    projects_list = _resolve_selected_vcpkg_projects(projects_list, sel_project)
    if test_mode:
        projects_list = projects_list[:10]
    count = 0
    os.environ["VCPKG_MAX_CONCURRENCY"] = str(os.cpu_count())
    for project_name in projects_list:
        vcpkg_json = VCPKG_LOCATION / "ports" / project_name / "vcpkg.json"
        executables = mt_vcpkg_blint_db_build(
            project_name,
            vcpkg_json,
            db_file=db_file,
            disassemble=disassemble,
        )
        print(f"Build complete for {project_name}. Got {len(executables)} binaries.")
        remove_vcpkg_project(project_name)
        count += 1
        if count == 10:
            remove_temp_ar()
            count = 0


def homebrew_add_blint_bom_process(
    *,
    db_file: str,
    disassemble: bool = False,
    test_mode: bool = False,
    sel_project: List | None = None,
):
    projects_list = (
        load_curated_homebrew_projects() if test_mode else get_homebrew_projects()
    )
    if test_mode:
        projects_list = _require_curated_projects(
            projects_list,
            ecosystem="Homebrew",
            curated_file=HOMEBREW_CURATED_FORMULAS_FILE,
        )
    projects_list = _resolve_selected_homebrew_projects(projects_list, sel_project)
    for formula_name in projects_list:
        executables = mt_homebrew_blint_db_build(
            formula_name,
            db_file=db_file,
            disassemble=disassemble,
        )
        print(f"Build complete for {formula_name}. Got {len(executables)} binaries.")


def cargo_add_blint_bom_process(
    *,
    db_file: str,
    disassemble: bool = False,
    test_mode: bool = False,
    sel_project: List | None = None,
):
    projects_list = (
        get_cargo_projects() if not test_mode else load_curated_cargo_projects()
    )
    if test_mode:
        projects_list = _require_curated_projects(
            projects_list,
            ecosystem="Cargo",
            curated_file=CARGO_CURATED_CRATES_FILE,
        )
    projects_list = _resolve_selected_cargo_projects(projects_list, sel_project)
    if test_mode and not sel_project:
        projects_list = projects_list[:CARGO_FEW_PACKAGES]
    for project_spec in projects_list:
        executables = mt_cargo_blint_db_build(
            project_spec,
            db_file=db_file,
            disassemble=disassemble,
        )
        print(
            f"Build complete for {project_spec.selector}. Got {len(executables)} binaries."
        )


def conan_add_blint_bom_process(
    *,
    db_file: str,
    disassemble: bool = False,
    test_mode: bool = False,
    sel_project: List | None = None,
):
    projects_list = _require_curated_projects(
        load_curated_conan_projects(),
        ecosystem="Conan",
        curated_file=CONAN_CURATED_PACKAGES_FILE,
    )
    projects_list = _resolve_selected_conan_projects(projects_list, sel_project)
    if test_mode and not sel_project:
        projects_list = projects_list[:CONAN_FEW_PACKAGES]
    for project_spec in projects_list:
        executables = mt_conan_blint_db_build(
            project_spec,
            db_file=db_file,
            disassemble=disassemble,
        )
        print(
            f"Build complete for {project_spec.selector}. Got {len(executables)} binaries."
        )


def _run_ingest(args):
    project_name = args.project_name or infer_project_name(
        args.input, args.metadata_file
    )
    build_metadata = _parse_json_argument(args.build_metadata_json)
    if args.metadata_file:
        result = ingest_metadata_file(
            args.metadata_file,
            db_file=args.db_file,
            project_name=project_name,
            project_purl=args.project_purl,
            ecosystem=args.ecosystem,
            project_metadata_file=args.project_metadata_file,
            source_sbom_file=args.source_sbom_file,
            build_system=args.build_system,
            target_os=args.target_os,
            target_arch=args.target_arch,
            target_triplet=args.target_triplet,
            build_mode=args.build_mode,
            optimization=args.optimization,
            strip_status=args.strip_status,
            build_metadata=build_metadata,
            binary_file_path=args.input,
            relative_to=args.relative_to,
        )
    elif args.input:
        result = ingest_binary_file(
            args.input,
            db_file=args.db_file,
            project_name=project_name,
            project_purl=args.project_purl,
            ecosystem=args.ecosystem,
            project_metadata=_parse_json_argument(None),
            source_sbom=None,
            build_system=args.build_system,
            target_os=args.target_os,
            target_arch=args.target_arch,
            target_triplet=args.target_triplet,
            build_mode=args.build_mode,
            optimization=args.optimization,
            strip_status=args.strip_status,
            build_metadata=build_metadata,
            relative_to=args.relative_to,
            disassemble=args.disassemble,
        )
    else:
        raise SystemExit(
            "Provide either --input or --metadata-file for the ingest command."
        )
    print(
        f"Ingested binary_id={result['binary_id']} build_id={result['build_id']} "
        f"project_id={result['project_id']}"
    )


def main():
    args = arguments_parser()
    command = _resolve_command(args)
    if not command:
        build_parser().print_help()
        return
    if args.clean:
        clear_sqlite_database(args.db_file)
    create_database(args.db_file)
    if command == "ingest":
        _run_ingest(args)
    elif command == "build-meson":
        meson_add_blint_bom_process(
            db_file=args.db_file,
            disassemble=args.disassemble,
            test_mode=args.test_mode,
            sel_project=args.sel_project,
        )
        metadata_path = write_run_metadata(
            command=command,
            db_file=args.db_file,
            metadata_file=args.run_metadata_file,
            disassemble=args.disassemble,
            test_mode=args.test_mode,
            selected_projects=args.sel_project,
        )
        print(f"Wrote build metadata to {metadata_path}")
    elif command == "build-vcpkg":
        vcpkg_add_blint_bom_process(
            db_file=args.db_file,
            disassemble=args.disassemble,
            test_mode=args.test_mode,
            sel_project=args.sel_project,
        )
        metadata_path = write_run_metadata(
            command=command,
            db_file=args.db_file,
            metadata_file=args.run_metadata_file,
            disassemble=args.disassemble,
            test_mode=args.test_mode,
            selected_projects=args.sel_project,
        )
        print(f"Wrote build metadata to {metadata_path}")
    elif command == "build-homebrew":
        homebrew_add_blint_bom_process(
            db_file=args.db_file,
            disassemble=args.disassemble,
            test_mode=args.test_mode,
            sel_project=args.sel_project,
        )
        metadata_path = write_run_metadata(
            command=command,
            db_file=args.db_file,
            metadata_file=args.run_metadata_file,
            disassemble=args.disassemble,
            test_mode=args.test_mode,
            selected_projects=args.sel_project,
        )
        print(f"Wrote build metadata to {metadata_path}")
    elif command == "build-cargo":
        cargo_add_blint_bom_process(
            db_file=args.db_file,
            disassemble=args.disassemble,
            test_mode=args.test_mode,
            sel_project=args.sel_project,
        )
        metadata_path = write_run_metadata(
            command=command,
            db_file=args.db_file,
            metadata_file=args.run_metadata_file,
            disassemble=args.disassemble,
            test_mode=args.test_mode,
            selected_projects=args.sel_project,
        )
        print(f"Wrote build metadata to {metadata_path}")
    elif command == "build-conan":
        conan_add_blint_bom_process(
            db_file=args.db_file,
            disassemble=args.disassemble,
            test_mode=args.test_mode,
            sel_project=args.sel_project,
        )
        metadata_path = write_run_metadata(
            command=command,
            db_file=args.db_file,
            metadata_file=args.run_metadata_file,
            disassemble=args.disassemble,
            test_mode=args.test_mode,
            selected_projects=args.sel_project,
        )
        print(f"Wrote build metadata to {metadata_path}")


if __name__ == "__main__":
    main()
