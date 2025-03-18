# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import os
import shutil
import subprocess
import sys
from pathlib import Path

from blint_db import DEBUG_MODE, WRAPDB_HASH, WRAPDB_LOCATION, WRAPDB_URL, logger
from blint_db.handlers.git_handler import git_checkout_commit, git_clone
from blint_db.handlers.language_handlers import BaseHandler
from blint_db.utils.utils import subprocess_run_debug, is_exe


cpu_count = os.cpu_count()

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
    logger.info(f"Building {project_name}")
    setup_command = f"meson setup build/{project_name} -Dwraps={project_name} -Dbuildtype=debug -Ddefault_library=shared -Dstrip=true -Dc_thread_count={cpu_count} -Dcpp_thread_count={cpu_count}".split(" ")
    meson_setup = subprocess.run(setup_command, cwd=WRAPDB_LOCATION, stdout=subprocess.DEVNULL, check=False,
                                 env=os.environ.copy(), capture_output=DEBUG_MODE, shell=sys.platform == "win32",
                                 encoding="utf-8")
    subprocess_run_debug(meson_setup, project_name)
    compile_command = "meson compile".split(" ")
    meson_compile = subprocess.run(compile_command, cwd=os.path.join(WRAPDB_LOCATION, "build", project_name),
                                   stdout=subprocess.DEVNULL, check=False, env=os.environ.copy(),
                                   capture_output=DEBUG_MODE, shell=sys.platform == "win32", encoding="utf-8")
    subprocess_run_debug(meson_compile, project_name)


def find_meson_executables(project_name):
    full_project_dir = WRAPDB_LOCATION / "build" / project_name / "subprojects"
    executable_list = []
    for root, dir, files in os.walk(full_project_dir):
        if "__pycache__" in root:
            continue
        for file in files:
            # what is the value of variable `root`
            file_path = Path(root) / file
            if is_exe(str(file_path)):
                executable_list.append(file_path)
    return executable_list


def strip_executables(file_path, loc=WRAPDB_LOCATION):
    strip_command = f"/usr/local/opt/binutils/bin/strip --strip-all {file_path}".split(" ")
    subprocess.run(strip_command, cwd=loc, check=False, env=os.environ.copy(), shell=sys.platform == "win32",
                   encoding="utf-8")
