# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import logging
import os
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)
logging.basicConfig(
    filename="info.log", format="cli.py:%(levelname)s:%(message)s", level=logging.DEBUG
)

DELIMETER_BOM = "~~"
# variables
DEBUG_MODE = True
# constants
TEMP_PATH = Path(os.getenv("BLINT_DB_TEMP", str(Path.cwd()))) / "temp"
WRAPDB_LOCATION = TEMP_PATH / "wrapdb"
VCPKG_LOCATION = TEMP_PATH / "vcpkg"

WRAPDB_URL = "https://github.com/mesonbuild/wrapdb.git"
VCPKG_URL = "https://github.com/microsoft/vcpkg.git"

WRAPDB_HASH = "dcb070e9bbb15ce72a7954fb92855a90d63669be"
VCPKG_HASH = "e9eda77e971179c933d78a3aec546527687b10be"

BOM_LOCATION = TEMP_PATH / "BOM"
BLINTDB_LOCATION = "blint.db"
CWD = Path(os.getcwd())

SQLITE_TIMEOUT = 20.0

COMMON_CONNECTION = None
# COMMON_CONNECTION = sqlite3.connect(":memory:")

VCPKG_ARCH_OS = "x64-linux"
