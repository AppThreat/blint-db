# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
import json
import os
import subprocess
import traceback
from sqlite3 import OperationalError

from blint_db import (
    ARCH,
    DEBUG_MODE,
    SYSTEM,
    VCPKG_COMMIT_HASH,
    VCPKG_DEFAULT_TRIPLET,
    VCPKG_LOCATION,
    VCPKG_URL,
    logger,
)
from blint_db.handlers.git_handler import git_checkout_commit, git_clone
from blint_db.handlers.language_handlers.vcpkg_handler import (
    find_vcpkg_executables,
    vcpkg_build,
)
from blint_db.ingest import ingest_binary_file


def git_clone_vcpkg():
    git_clone(VCPKG_URL, VCPKG_LOCATION)


def git_checkout_vcpkg_commit():
    git_checkout_commit(VCPKG_LOCATION, VCPKG_COMMIT_HASH)


def run_vcpkg_install_command():
    # Linux command
    install_command = ["bash", "bootstrap-vcpkg.sh"]
    install_run = subprocess.run(
        install_command,
        cwd=VCPKG_LOCATION,
        capture_output=True,
        check=False,
        encoding="utf-8",
    )
    if DEBUG_MODE:
        logger.debug(f"'bootstrap-vcpkg.sh: {install_run.stdout}")

    int_command = "./vcpkg integrate install".split(" ")
    int_run = subprocess.run(
        int_command,
        cwd=VCPKG_LOCATION,
        capture_output=True,
        check=False,
        encoding="utf-8",
    )
    if DEBUG_MODE:
        logger.debug(f"'vcpkg integrate install: {int_run.stdout}")


def exec_explorer(directory):
    """
    Walks through a directory and identifies executable files using the `file` command.

    Args:
      directory: The directory to search.

    Returns:
      A list of executable file paths.
    """
    executables = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            executables.append(file_path)
    return executables


def add_project_vcpkg_db(project_name, vcpkg_json, db_file=None, disassemble=False):
    purl = None
    metadata = None
    if vcpkg_json and os.path.exists(vcpkg_json):
        with open(vcpkg_json, encoding="utf-8") as fp:
            try:
                vcpkg_metadata = json.load(fp)
                purl = (
                    f"pkg:generic/{vcpkg_metadata['name']}@{vcpkg_metadata['version']}"
                    if vcpkg_metadata.get("version")
                    else f"pkg:generic/{vcpkg_metadata['name']}"
                )
                description = vcpkg_metadata.get("description")
                metadata = {
                    "description": description,
                    "dependencies": vcpkg_metadata.get("dependencies"),
                }
            except json.JSONDecodeError as e:
                logger.error(e)
    build_result = vcpkg_build(project_name)
    if getattr(build_result, "returncode", 1) != 0:
        raise RuntimeError(f"vcpkg build failed for {project_name}")
    execs = find_vcpkg_executables(project_name)
    for files in execs:
        try:
            ingest_binary_file(
                files,
                db_file=db_file,
                project_name=project_name,
                project_purl=purl,
                ecosystem="vcpkg",
                project_metadata=metadata,
                build_system="vcpkg",
                target_os=SYSTEM,
                target_arch=ARCH,
                target_triplet=VCPKG_DEFAULT_TRIPLET,
                build_mode="debug+release",
                strip_status="unstripped",
                build_metadata={"vcpkg_json": str(vcpkg_json)} if vcpkg_json else None,
                relative_to=VCPKG_LOCATION / "installed" / VCPKG_DEFAULT_TRIPLET,
                disassemble=disassemble,
            )
        except (RuntimeError, FileNotFoundError) as e:
            logger.info(f"error encountered with {project_name}")
            logger.error(e)
            logger.error(traceback.format_exc())
    return execs


def mt_vcpkg_blint_db_build(project_name, vcpkg_json, db_file=None, disassemble=False):
    logger.debug(f"Running {project_name} with vcpkg {vcpkg_json}")
    try:
        execs = add_project_vcpkg_db(
            project_name,
            vcpkg_json,
            db_file=db_file,
            disassemble=disassemble,
        )
        return execs
    except OperationalError as e:
        logger.info(f"error encountered with {project_name}")
        logger.error(e)
        logger.error(traceback.format_exc())
        return []
