# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
import json
import os
import subprocess
import traceback
from sqlite3 import OperationalError

from blint_db import DEBUG_MODE, VCPKG_HASH, VCPKG_LOCATION, VCPKG_URL, logger
from blint_db.handlers.blint_handler import get_blint_internal_functions_exe
from blint_db.handlers.git_handler import git_checkout_commit, git_clone
from blint_db.handlers.language_handlers.vcpkg_handler import (
    find_vcpkg_executables, vcpkg_build)
from blint_db.handlers.sqlite_handler import (add_binary, add_binary_export,
                                              add_projects)


def git_clone_vcpkg():
    git_clone(VCPKG_URL, VCPKG_LOCATION)


def git_checkout_vcpkg_commit():
    git_checkout_commit(VCPKG_LOCATION, VCPKG_HASH)


def run_vcpkg_install_command():
    # Linux command
    install_command = ["bash", "bootstrap-vcpkg.sh"]
    install_run = subprocess.run(
        install_command, cwd=VCPKG_LOCATION, capture_output=True, check=False, encoding="utf-8"
    )
    if DEBUG_MODE:
        logger.debug(f"'bootstrap-vcpkg.sh: {install_run.stdout}")

    int_command = "./vcpkg integrate install".split(" ")
    int_run = subprocess.run(
        int_command, cwd=VCPKG_LOCATION, capture_output=True, check=False, encoding="utf-8"
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


def add_project_vcpkg_db(project_name, vcpkg_json):
    purl = None
    metadata = None
    if vcpkg_json and os.path.exists(vcpkg_json):
        with open(vcpkg_json, encoding="utf-8") as fp:
            try:
                vcpkg_metadata = json.load(fp)
                purl = f"pkg:generic/{vcpkg_metadata['name']}@{vcpkg_metadata['version']}" if vcpkg_metadata.get("version") else f"pkg:generic/{vcpkg_metadata['name']}"
                description = vcpkg_metadata.get("description")
                metadata = {"description": description, "dependencies": vcpkg_metadata.get("dependencies")}
            except json.JSONDecodeError as e:
                logger.error(e)
    pid = add_projects(project_name, purl=purl, metadata=metadata)
    vcpkg_build(project_name)
    execs = find_vcpkg_executables(project_name)
    for files in execs:
        try:
            bid = add_binary(files, pid, split_word="packages/")
            if_list = get_blint_internal_functions_exe(files)
            for func in if_list:
                add_binary_export(func, bid)
        except (RuntimeError, FileNotFoundError) as e:
            logger.info(f"error encountered with {project_name}")
            logger.error(e)
            logger.error(traceback.format_exc())
    return execs


def mt_vcpkg_blint_db_build(project_name, vcpkg_json):
    logger.debug(f"Running {project_name} with vcpkg {vcpkg_json}")
    try:
        execs = add_project_vcpkg_db(project_name, vcpkg_json)
        return execs
    except OperationalError as e:
        logger.info(f"error encountered with {project_name}")
        logger.error(e)
        logger.error(traceback.format_exc())
        return []
