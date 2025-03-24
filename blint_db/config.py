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

WRAPDB_COMMIT_HASH = "43207fb8c0423b18173eeb37de8056e071d72fa7"
VCPKG_COMMIT_HASH = "a76b33254af4092ff45f08ec5adcd9fd06468b43"

BOM_LOCATION = BLINT_DB_BOOTSTRAP_PATH / "BOM"
BLINT_DB_FILE = "blint.db"
CWD = Path(os.getcwd())

SQLITE_TIMEOUT = 20.0

COMMON_CONNECTION = None
ARCH = platform.machine()
SYSTEM = platform.system().lower()
if ARCH == "x86_64":
    ARCH = "x64"
if ARCH == "aarch64":
    ARCH = "arm64"
if SYSTEM == "darwin":
    SYSTEM = "osx"
VCPKG_ARCH_OS = f"{ARCH}-{SYSTEM}"

for log_name, log_obj in logging.Logger.manager.loggerDict.items():
    if log_name != __name__:
        log_obj.disabled = True
