# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
import configparser
import os
import shutil
import traceback
from sqlite3 import OperationalError

from blint_db import WRAPDB_HASH, WRAPDB_LOCATION, WRAPDB_URL, logger
from blint_db.handlers.blint_handler import get_blint_internal_functions_exe
from blint_db.handlers.git_handler import git_checkout_commit, git_clone
from blint_db.handlers.language_handlers.meson_handler import (
    find_meson_executables, meson_build, strip_executables)
from blint_db.handlers.sqlite_handler import (add_binary, add_binary_export,
                                              add_projects)


def git_clone_wrapdb():
    git_clone(WRAPDB_URL, WRAPDB_LOCATION)


def git_checkout_wrapdb_commit():
    git_checkout_commit(WRAPDB_LOCATION, WRAPDB_HASH)


def ensure_meson_installed():
    return shutil.which("meson") is not None


def add_project_meson_db(project_name, wrap_file):
    purl = None
    metadata = None
    if wrap_file and os.path.exists(wrap_file):
        config = configparser.ConfigParser()
        config.read(wrap_file)
        source_hash = config.get("wrap-file", {}).get("source_hash")
        directory = config.get("wrap-file", {}).get("directory")
        purl = f"pkg:generic/{directory}@{source_hash}"
        metadata = {"source_url", config.get("wrap-file", {}).get("source_url")}
    pid = add_projects(project_name, purl=purl, metadata=metadata)
    meson_build(project_name)
    execs = find_meson_executables(project_name)
    for files in execs:
        try:
            strip_executables(files)
            bid = add_binary(files, pid)
            if_list = get_blint_internal_functions_exe(files)
            for func in if_list:
                add_binary_export(func, bid)
            # TODO: delete project after done processing
        except (RuntimeError, FileNotFoundError) as e:
            logger.info(f"error encountered with {project_name}")
            logger.error(e)
            logger.error(traceback.format_exc())
    return execs


def mt_meson_blint_db_build(project_name_wrap_tuple):
    project_name, wrap_file = project_name_wrap_tuple
    logger.debug(f"Running {project_name}")
    try:
        execs = add_project_meson_db(project_name, wrap_file)
        logger.info(f"Completed: {project_name} with execs:{len(execs)}")
    except OperationalError as e:
        logger.info(f"error encountered with {project_name}")
        logger.error(e)
        logger.error(traceback.format_exc())
        return [False]
    return execs


def st_meson_blint_db_build(project_list):
    # returns executables list so we can run blint on them
    executables_list = []
    for project_name in project_list:
        execs = add_project_meson_db(project_name)

        executables_list.extend(execs)
    return executables_list
