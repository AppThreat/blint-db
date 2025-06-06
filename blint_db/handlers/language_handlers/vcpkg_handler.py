# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import os
import shutil
import subprocess

from blint_db import (VCPKG_ARCH_OS, DEBUG_MODE, VCPKG_COMMIT_HASH, VCPKG_LOCATION,
                      VCPKG_URL, logger)
from blint_db.handlers.git_handler import git_checkout_commit, git_clone
from blint_db.handlers.language_handlers import BaseHandler
from blint_db.utils import subprocess_run_debug, get_executables


class VcpkgHandler(BaseHandler):
    strip = False

    def __init__(self):
        git_clone(VCPKG_URL, VCPKG_LOCATION)
        git_checkout_commit(VCPKG_LOCATION, VCPKG_COMMIT_HASH)
        run_vcpkg_install_command()

    def build(self, project_name):
        inst_cmd = f"./vcpkg install {project_name}".split(" ")
        inst_run = subprocess.run(
            inst_cmd, cwd=VCPKG_LOCATION, stdout=subprocess.DEVNULL, capture_output=DEBUG_MODE, check=False, encoding="utf-8"
        )
        subprocess_run_debug(inst_run, project_name)

    def find_executables(self, project_name):
        project_path = f"{project_name}_{VCPKG_ARCH_OS}"
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
    git_checkout_commit(VCPKG_LOCATION, VCPKG_COMMIT_HASH)


def run_vcpkg_install_command():
    # Linux command
    install_command = ["bash", "bootstrap-vcpkg.sh"]
    install_run = subprocess.run(
        install_command, cwd=VCPKG_LOCATION, stdout=subprocess.DEVNULL, capture_output=DEBUG_MODE, check=False, encoding="utf-8"
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
    subprocess.run(int_command, cwd=VCPKG_LOCATION, stdout=subprocess.DEVNULL, capture_output=DEBUG_MODE, check=False, encoding="utf-8")


def remove_vcpkg_project(project_name):
    rem_cmd = ["./vcpkg", "remove", "--recurse", project_name]
    rem_run = subprocess.run(
        rem_cmd, cwd=VCPKG_LOCATION, capture_output=DEBUG_MODE, check=False, encoding="utf-8"
    )
    subprocess_run_debug(rem_run, project_name)
    shutil.rmtree(VCPKG_LOCATION / "packages" / project_name, ignore_errors=True)


def get_vcpkg_projects():
    ports_path = VCPKG_LOCATION / "ports"
    if not os.path.exists(ports_path):
        git_clone_vcpkg()
        git_checkout_vcpkg_commit()
    run_vcpkg_install_command()

    return os.listdir(ports_path)


def vcpkg_build(project_name):
    logger.info(f"Building {project_name}")
    inst_cmd = ["./vcpkg", "install", "--keep-going", project_name]
    inst_run = subprocess.run(
        inst_cmd, cwd=VCPKG_LOCATION, stdout=subprocess.DEVNULL, capture_output=DEBUG_MODE, check=False, encoding="utf-8"
    )
    subprocess_run_debug(inst_run, project_name)


def find_vcpkg_executables(project_name):
    project_path = f"{project_name}_{VCPKG_ARCH_OS}"
    target_directory = VCPKG_LOCATION / "packages" / project_path
    # If the package generates multiple binaries then the target directory could be empty
    exes = get_executables(target_directory)
    if not exes and os.path.exists(VCPKG_LOCATION / "packages"):
        project_dirs = []
        for f in os.listdir(VCPKG_LOCATION / "packages"):
            if os.path.isdir(f) and f.startswith(project_name.split("-")[0]):
                project_dirs.append(f)
        if project_dirs:
            print(project_name, "has multiple packages", project_dirs)
            for d in project_dirs:
                exes = exes + get_executables(d)
    if not exes:
        print ("Unable to find any binaries for", project_name, target_directory)
    return exes
