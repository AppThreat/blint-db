# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
import shutil
from pathlib import Path

from blint_db import (
    BUILD_JOBS,
    MESON_BUILD_TYPE,
    MESON_DEFAULT_LIBRARY,
    MESON_EXTRA_COMPILE_ARGS,
    MESON_EXTRA_SETUP_ARGS,
    MESON_STRIP,
    MESON_WARN_LEVEL,
    WRAPDB_COMMIT_HASH,
    WRAPDB_LOCATION,
    WRAPDB_URL,
    logger,
)
from blint_db.handlers.git_handler import git_checkout_commit, git_clone
from blint_db.handlers.language_handlers import BaseHandler
from blint_db.utils import get_executables, run_command

MESON_EXECUTABLE: str = "meson"


class MesonHandler(BaseHandler):
    def __init__(self):
        if shutil.which(str(MESON_EXECUTABLE)) is None:
            raise ModuleNotFoundError("Meson was not found")
        git_clone(WRAPDB_URL, WRAPDB_LOCATION)
        git_checkout_commit(WRAPDB_LOCATION, WRAPDB_COMMIT_HASH)

    def delete_project_files(self, project_name):
        build_dir = WRAPDB_LOCATION / "build" / project_name
        shutil.rmtree(build_dir, ignore_errors=True)

    def get_project_list(self):
        subproject_filenames = os.listdir(WRAPDB_LOCATION / "subprojects")
        projects_list = []
        for file in subproject_filenames:
            project_path = Path(file)
            if project_path.suffix == ".wrap":
                projects_list.append(project_path.stem)
        return projects_list


def build_dir_for(project_name: str) -> Path:
    return WRAPDB_LOCATION / "build" / project_name


def meson_setup_command(project_name: str) -> list[str]:
    build_dir = build_dir_for(project_name)
    command = [
        MESON_EXECUTABLE,
        "setup",
        str(build_dir),
        f"-Dwraps={project_name}",
        f"-Dbuildtype={MESON_BUILD_TYPE}",
        f"-Ddefault_library={MESON_DEFAULT_LIBRARY}",
        f"-Dstrip={str(MESON_STRIP).lower()}",
        f"-Dc_thread_count={BUILD_JOBS}",
        f"-Dcpp_thread_count={BUILD_JOBS}",
        "--warnlevel",
        MESON_WARN_LEVEL,
    ]
    command.extend(MESON_EXTRA_SETUP_ARGS)
    return command


def meson_compile_command(project_name: str) -> list[str]:
    command = [
        MESON_EXECUTABLE,
        "compile",
        "-C",
        str(build_dir_for(project_name)),
        "-j",
        str(BUILD_JOBS),
    ]
    command.extend(MESON_EXTRA_COMPILE_ARGS)
    return command


def _is_meson_build_intermediate(file_path: str | Path) -> bool:
    path_obj = Path(file_path)
    if any(part.endswith(".p") for part in path_obj.parts):
        return True
    return path_obj.suffix.lower() in {".o", ".obj", ".lo", ".pdb", ".ilk"}


def _is_supported_meson_artifact(file_path: str | Path) -> bool:
    path_obj = Path(file_path)
    if _is_meson_build_intermediate(path_obj):
        return False
    if path_obj.name.endswith(("_objlib.a", "_objlib.lib")):
        return False
    if path_obj.suffix.lower() in {".a", ".lib", ".so", ".dylib", ".dll", ".wasm"}:
        return True
    return os.access(path_obj, os.X_OK)


def meson_build(project_name):
    logger.info(f"Building {project_name}")
    build_dir = build_dir_for(project_name)
    shutil.rmtree(build_dir, ignore_errors=True)
    setup_command = meson_setup_command(project_name)
    meson_setup = run_command(
        setup_command, cwd=WRAPDB_LOCATION, project_name=project_name
    )
    if meson_setup.returncode != 0:
        return meson_setup
    compile_command = meson_compile_command(project_name)
    return run_command(compile_command, cwd=WRAPDB_LOCATION, project_name=project_name)


def find_meson_executables(project_name):
    full_project_dir = build_dir_for(project_name) / "subprojects"
    return sorted(
        file_path
        for file_path in get_executables(full_project_dir)
        if _is_supported_meson_artifact(file_path)
    )
