# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
import shutil
from pathlib import Path

from blint_db import (
    BUILD_JOBS,
    DEBUG_MODE,
    VCPKG_ARCH_OS,
    VCPKG_COMMIT_HASH,
    VCPKG_DEFAULT_TRIPLET,
    VCPKG_EXTRA_INSTALL_ARGS,
    VCPKG_KEEP_GOING,
    VCPKG_LOCATION,
    VCPKG_URL,
    logger,
)
from blint_db.handlers.git_handler import git_checkout_commit, git_clone
from blint_db.handlers.language_handlers import BaseHandler
from blint_db.utils import get_executables, is_exe, run_command, subprocess_run_debug


class VcpkgHandler(BaseHandler):
    strip = False

    def __init__(self):
        git_clone(VCPKG_URL, VCPKG_LOCATION)
        git_checkout_commit(VCPKG_LOCATION, VCPKG_COMMIT_HASH)
        run_vcpkg_install_command()

    def build(self, project_name):
        return vcpkg_build(project_name)

    def find_executables(self, project_name):
        project_path = f"{project_name}_{VCPKG_ARCH_OS}"
        target_directory = VCPKG_LOCATION / "packages" / project_path
        return get_executables(target_directory)

    def delete_project_files(self, project_name):
        remove_vcpkg_project(project_name)

    def get_project_list(self):
        ports_path = VCPKG_LOCATION / "ports"
        return sorted(os.listdir(ports_path))


def git_clone_vcpkg():
    git_clone(VCPKG_URL, VCPKG_LOCATION)


def git_checkout_vcpkg_commit():
    git_checkout_commit(VCPKG_LOCATION, VCPKG_COMMIT_HASH)


def _vcpkg_executable() -> str:
    return "./vcpkg"


def vcpkg_install_command(project_name: str) -> list[str]:
    command = [
        _vcpkg_executable(),
        "install",
        *(["--keep-going"] if VCPKG_KEEP_GOING else []),
        "--clean-after-build",
        f"--triplet={VCPKG_DEFAULT_TRIPLET}",
        f"--x-buildtrees-root={VCPKG_LOCATION / 'buildtrees'}",
        f"--x-packages-root={VCPKG_LOCATION / 'packages'}",
        f"--x-install-root={VCPKG_LOCATION / 'installed'}",
        f"--x-builtin-ports-root={VCPKG_LOCATION / 'ports'}",
        project_name,
    ]
    command.extend(VCPKG_EXTRA_INSTALL_ARGS)
    return command


def run_vcpkg_install_command():
    install_command = ["bash", "bootstrap-vcpkg.sh", "-disableMetrics"]
    install_run = run_command(
        install_command, cwd=VCPKG_LOCATION, project_name="bootstrap-vcpkg"
    )
    if DEBUG_MODE:
        logger.debug(f"'bootstrap-vcpkg.sh: {install_run.stdout}")
    vcpkg_bin_file = os.path.join(VCPKG_LOCATION, "vcpkg")
    if os.path.exists(vcpkg_bin_file):
        logger.info("vcpkg is available")
    else:
        logger.info("vcpkg is not available")
        return
    int_command = [_vcpkg_executable(), "integrate", "install"]
    run_command(int_command, cwd=VCPKG_LOCATION, project_name="vcpkg-integrate")


def remove_vcpkg_project(project_name):
    rem_cmd = [_vcpkg_executable(), "remove", "--recurse", project_name]
    rem_run = run_command(rem_cmd, cwd=VCPKG_LOCATION, project_name=project_name)
    subprocess_run_debug(rem_run, project_name)

    for root_dir in (
        VCPKG_LOCATION / "packages",
        VCPKG_LOCATION / "buildtrees",
    ):
        if not root_dir.exists():
            continue
        for candidate in root_dir.iterdir():
            if candidate.is_dir() and candidate.name.startswith(project_name):
                shutil.rmtree(candidate, ignore_errors=True)

    info_dir = VCPKG_LOCATION / "installed" / "vcpkg" / "info"
    if info_dir.exists():
        for candidate in info_dir.glob(
            f"{project_name}_*_{VCPKG_DEFAULT_TRIPLET}.list"
        ):
            candidate.unlink(missing_ok=True)


def get_vcpkg_projects():
    ports_path = VCPKG_LOCATION / "ports"
    if not os.path.exists(ports_path):
        git_clone_vcpkg()
        git_checkout_vcpkg_commit()
    run_vcpkg_install_command()
    return sorted(os.listdir(ports_path))


def _installed_triplet_root() -> Path:
    return VCPKG_LOCATION / "installed" / VCPKG_DEFAULT_TRIPLET


def _is_supported_vcpkg_artifact(file_path: str | Path) -> bool:
    path_obj = Path(file_path)
    if not path_obj.exists() or not path_obj.is_file():
        return False
    if any(
        part in {"include", "share", "pkgconfig", "cmake", "man"}
        for part in path_obj.parts
    ):
        return False
    if path_obj.suffix.lower() in {
        ".a",
        ".lib",
        ".so",
        ".dylib",
        ".dll",
        ".wasm",
        ".exe",
    }:
        return True
    return is_exe(str(path_obj))


def _artifacts_from_installed_listfiles(project_name: str) -> list[str]:
    info_dir = VCPKG_LOCATION / "installed" / "vcpkg" / "info"
    triplet_root = _installed_triplet_root()
    if not info_dir.exists() or not triplet_root.exists():
        return []
    artifacts: list[str] = []
    for listfile in sorted(
        info_dir.glob(f"{project_name}_*_{VCPKG_DEFAULT_TRIPLET}.list")
    ):
        for raw_line in listfile.read_text(encoding="utf-8").splitlines():
            relative_path = raw_line.strip().rstrip("/")
            if not relative_path or relative_path.endswith("/"):
                continue
            if relative_path.startswith(f"{VCPKG_DEFAULT_TRIPLET}/"):
                relative_path = relative_path[len(VCPKG_DEFAULT_TRIPLET) + 1 :]
            candidate = triplet_root / relative_path
            if _is_supported_vcpkg_artifact(candidate):
                artifacts.append(str(candidate))
    return sorted(dict.fromkeys(artifacts))


def vcpkg_build(project_name):
    logger.info(f"Building {project_name}")
    env = os.environ.copy()
    env["VCPKG_MAX_CONCURRENCY"] = str(BUILD_JOBS)
    inst_cmd = vcpkg_install_command(project_name)
    return run_command(inst_cmd, cwd=VCPKG_LOCATION, env=env, project_name=project_name)


def find_vcpkg_executables(project_name):
    project_path = f"{project_name}_{VCPKG_ARCH_OS}"
    target_directory = VCPKG_LOCATION / "packages" / project_path
    exes = [
        file_path
        for file_path in get_executables(target_directory)
        if _is_supported_vcpkg_artifact(file_path)
    ]
    if not exes:
        exes = _artifacts_from_installed_listfiles(project_name)
    if not exes and os.path.exists(VCPKG_LOCATION / "packages"):
        project_dirs = []
        for package_dir in (VCPKG_LOCATION / "packages").iterdir():
            if package_dir.is_dir() and package_dir.name.startswith(
                project_name.split("-")[0]
            ):
                project_dirs.append(package_dir)
        if project_dirs:
            print(project_name, "has multiple packages", [d.name for d in project_dirs])
            for package_dir in project_dirs:
                exes.extend(
                    file_path
                    for file_path in get_executables(package_dir)
                    if _is_supported_vcpkg_artifact(file_path)
                )
    if not exes:
        print("Unable to find any binaries for", project_name, target_directory)
    return sorted(dict.fromkeys(exes))
