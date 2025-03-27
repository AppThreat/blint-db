# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import os
from pathlib import Path

from blint_db import DEBUG_MODE, VCPKG_LOCATION, WRAPDB_LOCATION, IGNORE_DIRECTORIES, logger

HOME_DIRECTORY = Path.home()


def _create_python_dirs():
    wl = WRAPDB_LOCATION
    vl = VCPKG_LOCATION

    os.makedirs(wl, exist_ok=True)
    os.makedirs(vl, exist_ok=True)


_create_python_dirs()

def subprocess_run_debug(setup_run, project_name):
    if DEBUG_MODE:
        if setup_run.stderr:
            logger.error(
                f"{project_name} failed to SETUP {WRAPDB_LOCATION / 'build' / project_name}"
            )
            logger.error(f"{project_name}: {setup_run.stderr}")


def is_binary_string(content):
    """
    Method to check if the given content is a binary string
    """
    textchars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
    return bool(content.translate(None, textchars))


def is_exe(src):
    """
    Detect if the source is a binary file

    Args:
        src: Source path

    Returns:
         bool: True if binary file. False otherwise.
    """
    if os.path.isfile(src):
        try:
            with open(src, "rb") as f:
                data = f.read(1024)
            return is_binary_string(data)
        except (TypeError, OverflowError, ValueError, OSError):
            return False
    return False


def filter_ignored_dirs(dirs):
    """
    Method to filter directory list to remove ignored directories

    :param dirs: Directories to ignore
    :return: Filtered directory list
    """
    [
        dirs.remove(d)
        for d in list(dirs)
        if d.lower() in IGNORE_DIRECTORIES or d.startswith(".")
    ]
    return dirs


def get_executables(directory):
    """
    Walks through a directory and identifies executable files

    Args:
      directory: The directory to search.

    Returns:
      A list of executable file paths.
    """
    if not os.path.exists(directory):
        return []
    executables = []
    for root, dirs, files in os.walk(directory):
        if "__pycache__" in root:
            continue
        filter_ignored_dirs(dirs)
        for file in files:
            file_path = os.path.join(root, file)
            if is_exe(file_path):
                executables.append(file_path)
    return executables
