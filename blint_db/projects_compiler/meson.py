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
    find_meson_executables, meson_build)
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
        try:
            config.read(wrap_file)
            source_hash = config["wrap-file"]["source_hash"]
            directory = config["wrap-file"]["directory"]
            name = directory
            version = None
            if "-" in name:
                tmp_a = name.split("-")
                if len(tmp_a) >= 2:
                    version = tmp_a[-1]
                    name = name.replace(f"-{version}", "")
            name_with_version = f"{name}@{version}" if version else name
            purl = f"pkg:generic/{name_with_version}?source_hash={source_hash}"
            metadata = {"source_url": config["wrap-file"]["source_url"]}
        except (configparser.NoSectionError, configparser.NoOptionError, configparser.InterpolationSyntaxError):
            logger.info(f"Unable to parse {wrap_file}")
            pass
        except Exception:
            pass
    pid = add_projects(project_name, purl=purl, metadata=metadata)
    meson_build(project_name)
    execs = find_meson_executables(project_name)
    for files in execs:
        try:
            # strip_executables(files)
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
    except OperationalError as e:
        logger.info(f"error encountered with {project_name}")
        logger.error(e)
        logger.error(traceback.format_exc())
        return []
    return execs
