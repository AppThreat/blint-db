# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import os
import subprocess
from pathlib import Path

HOME_DIRECTORY = Path.home()


def _config():
    from blint_db import config as config_module

    return config_module


def _wrapdb_location() -> Path:
    return _config().WRAPDB_LOCATION


def _vcpkg_location() -> Path:
    return _config().VCPKG_LOCATION


def _ignore_directories() -> list[str]:
    return _config().IGNORE_DIRECTORIES


def _debug_mode() -> bool:
    return _config().DEBUG_MODE


def _logger():
    return _config().logger


def _create_python_dirs():
    wl = _wrapdb_location()
    vl = _vcpkg_location()

    os.makedirs(wl, exist_ok=True)
    os.makedirs(vl, exist_ok=True)


def subprocess_run_debug(setup_run, project_name):
    if _debug_mode():
        if setup_run.stderr:
            _logger().error(
                f"{project_name} failed to SETUP {_wrapdb_location() / 'build' / project_name}"
            )
            _logger().error(f"{project_name}: {setup_run.stderr}")


def run_command(command, *, cwd=None, env=None, project_name=""):
    _create_python_dirs()
    result = subprocess.run(
        command,
        cwd=cwd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE if _debug_mode() else subprocess.DEVNULL,
        check=False,
        env=env or os.environ.copy(),
        encoding="utf-8",
    )
    subprocess_run_debug(result, project_name)
    return result


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
        if d.lower() in _ignore_directories() or d.startswith(".")
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
