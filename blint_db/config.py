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
TEMP_PATH = Path.cwd() / "temp"
WRAPDB_LOCATION = TEMP_PATH / "wrapdb"
VCPKG_LOCATION = TEMP_PATH / "vcpkg"

WRAPDB_URL = "https://github.com/mesonbuild/wrapdb.git"
VCPKG_URL = "https://github.com/microsoft/vcpkg.git"

WRAPDB_HASH = "90fdc28c75412d99900f2ff58006de57866c63ee"
VCPKG_HASH = "e60236ee051183f1122066bee8c54a0b47c43a60"

BOM_LOCATION = TEMP_PATH / "BOM"
BLINTDB_LOCATION = "blint.db"
CWD = Path(os.getcwd())

SQLITE_TIMEOUT = 20.0

COMMON_CONNECTION = None
# COMMON_CONNECTION = sqlite3.connect(":memory:")
