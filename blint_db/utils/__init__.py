import os
from pathlib import Path

from blint_db import VCPKG_LOCATION, DEBUG_MODE, WRAPDB_LOCATION

HOME_DIRECTORY = Path.home()


def _create_python_dirs():
    wl = WRAPDB_LOCATION
    vl = VCPKG_LOCATION
    
    os.makedirs(wl, exist_ok=True)
    os.makedirs(vl, exist_ok=True)

    if DEBUG_MODE:
        print(f"{wl} created")
        print(f"{vl} created")


_create_python_dirs()
