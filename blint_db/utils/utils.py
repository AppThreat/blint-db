# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
import os
from blint_db import DEBUG_MODE, WRAPDB_LOCATION, logger


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
        except (TypeError, OverflowError, ValueError, OSError) as e:
            return False
    return False
