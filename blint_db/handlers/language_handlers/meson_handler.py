# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import os
import shutil
import subprocess
import sys
from pathlib import Path

from blint_db import CWD, WRAPDB_HASH, WRAPDB_LOCATION, WRAPDB_URL
from blint_db.handlers.git_handler import git_checkout_commit, git_clone
from blint_db.handlers.language_handlers import BaseHandler
from blint_db.utils.utils import subprocess_run_debug


class MesonHandler(BaseHandler):

    def __init__(self):
        if not shutil.which("meson"):
            raise ModuleNotFoundError("Meson was not found")
        git_clone(WRAPDB_URL, WRAPDB_LOCATION)
        git_checkout_commit(WRAPDB_LOCATION, WRAPDB_HASH)

    def delete_project_files(self, project_name):
        pass

    def get_project_list(self):
        subproject_filenames = os.listdir(WRAPDB_LOCATION / "subprojects")
        projects_list = []
        for file in subproject_filenames:
            project_path = Path(file)
            if project_path.suffix == ".wrap":
                projects_list.append(project_path.stem)
        return projects_list


def meson_build(project_name):
    setup_command = f"meson setup build/{project_name} -Dwraps={project_name}".split(" ")
    meson_setup = subprocess.run(setup_command, cwd=WRAPDB_LOCATION, check=False, env=os.environ.copy(), shell=sys.platform == "win32", encoding="utf-8")
    subprocess_run_debug(meson_setup, project_name)
    compile_command = "meson compile".split(" ")
    meson_compile = subprocess.run(compile_command, cwd=os.path.join(WRAPDB_LOCATION, "build", project_name), check=False, env=os.environ.copy(), shell=sys.platform == "win32", encoding="utf-8")
    subprocess_run_debug(meson_compile, project_name)


def find_meson_executables(project_name):
    full_project_dir = WRAPDB_LOCATION / "build" / project_name / "subprojects"
    executable_list = []
    for root, dir, files in os.walk(full_project_dir):
        for file in files:
            # what is the value of variable `root`
            file_path = Path(root) / file
            if os.access(file_path, os.X_OK) or ".so" in str(file_path):
                executable_list.append(file_path)
    return executable_list


def strip_executables(file_path, loc=WRAPDB_LOCATION):
    strip_command = f"/usr/local/opt/binutils/bin/strip --strip-all {file_path}".split(" ")
    subprocess.run(strip_command, cwd=loc, check=False, env=os.environ.copy(), shell=sys.platform == "win32", encoding="utf-8")
