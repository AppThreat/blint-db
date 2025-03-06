# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import os
import subprocess
import stat

from blint_db import (VCPKG_ARCH_OS, DEBUG_MODE, VCPKG_HASH, VCPKG_LOCATION,
                      VCPKG_URL, logger)
from blint_db.handlers.git_handler import git_checkout_commit, git_clone
from blint_db.handlers.language_handlers import BaseHandler
from blint_db.utils.utils import subprocess_run_debug, is_exe


class VcpkgHandler(BaseHandler):
    strip = False

    def __init__(self):
        git_clone(VCPKG_URL, VCPKG_LOCATION)
        git_checkout_commit(VCPKG_LOCATION, VCPKG_HASH)
        run_vcpkg_install_command()

    def build(self, project_name):
        inst_cmd = f"./vcpkg install {project_name}".split(" ")
        inst_run = subprocess.run(
            inst_cmd, cwd=VCPKG_LOCATION, capture_output=True, check=False, encoding="utf-8"
        )
        subprocess_run_debug(inst_run, project_name)

    def find_executables(self, project_name):
        project_path = f"{project_name}_x64-linux"
        target_directory = VCPKG_LOCATION / "packages" / project_path
        return exec_explorer(target_directory)

    def delete_project_files(self, project_name):
        pass

    def get_project_list(self):
        ports_path = VCPKG_LOCATION / "ports"
        return os.listdir(ports_path)


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
    vcpkg_bin_file = os.path.join(VCPKG_LOCATION, "vcpkg")
    if os.path.exists(vcpkg_bin_file):
        logger.info("vcpkg is available")
    else:
        logger.info("vcpkg is not available")
        return
    int_command = "./vcpkg integrate install".split(" ")
    int_run = subprocess.run(int_command, cwd=VCPKG_LOCATION, capture_output=True, encoding="utf-8")
    if DEBUG_MODE:
        logger.debug(f"'vcpkg integrate install: {int_run.stdout}")


def remove_vcpkg_project(project_name):
    rem_cmd = ["./vcpkg", "remove", "--recurse", project_name]
    rem_run = subprocess.run(
        rem_cmd, cwd=VCPKG_LOCATION, capture_output=True, check=False, encoding="utf-8"
    )
    subprocess_run_debug(rem_run, project_name)


def get_vcpkg_projects():
    ports_path = VCPKG_LOCATION / "ports"
    if not os.path.exists(ports_path):
        git_clone_vcpkg()
        git_checkout_vcpkg_commit()
    run_vcpkg_install_command()

    return os.listdir(ports_path)


def vcpkg_build(project_name):
    inst_cmd = ["./vcpkg", "install", "--clean-downloads-after-build", project_name]
    inst_run = subprocess.run(
        inst_cmd, cwd=VCPKG_LOCATION, capture_output=True, check=False, encoding="utf-8"
    )
    subprocess_run_debug(inst_run, project_name)


def find_vcpkg_executables(project_name):
    project_path = f"{project_name}_{VCPKG_ARCH_OS}"
    target_directory = VCPKG_LOCATION / "packages" / project_path
    return exec_explorer(target_directory)


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
            if is_exe(file_path):
                executables.append(file_path)
    return executables
