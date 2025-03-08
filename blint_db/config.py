# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import logging
import os
import platform
from pathlib import Path

logger = logging.getLogger(__name__)
logging.basicConfig(
    format="%(message)s", level=logging.INFO
)

DELIMETER_BOM = "~~"
DEBUG_MODE = False

BLINT_DB_BOOTSTRAP_PATH = Path(os.getenv("BLINT_DB_BOOTSTRAP_PATH", str(Path.cwd() / "temp")))
WRAPDB_LOCATION = BLINT_DB_BOOTSTRAP_PATH / "wrapdb"
VCPKG_LOCATION = BLINT_DB_BOOTSTRAP_PATH / "vcpkg"

WRAPDB_URL = "https://github.com/mesonbuild/wrapdb.git"
VCPKG_URL = "https://github.com/microsoft/vcpkg.git"

WRAPDB_HASH = "dcb070e9bbb15ce72a7954fb92855a90d63669be"
VCPKG_HASH = "e9eda77e971179c933d78a3aec546527687b10be"

BOM_LOCATION = BLINT_DB_BOOTSTRAP_PATH / "BOM"
BLINT_DB_FILE = "blint.db"
CWD = Path(os.getcwd())

SQLITE_TIMEOUT = 20.0

COMMON_CONNECTION = None
ARCH = platform.machine()
SYSTEM = platform.system().lower()
if ARCH == "x86_64":
    ARCH = "x64"
if SYSTEM == "darwin":
    SYSTEM = "osx"
VCPKG_ARCH_OS = f"{ARCH}-{SYSTEM}"

for log_name, log_obj in logging.Logger.manager.loggerDict.items():
    if log_name != __name__:
        log_obj.disabled = True
