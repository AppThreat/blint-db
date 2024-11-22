# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import subprocess
from pathlib import Path

from blint_db import BOM_LOCATION, DEBUG_MODE, DELIMETER_BOM, WRAPDB_LOCATION
from blint_db.utils.json import get_properties_internal


def run_blint_on_file(file_path):
    # TODO: assume blint installed
    blint_command = [
        "blint",
        "sbom",
        "--deep",
        "-o",
        f"{file_path}.json",
        "-i",
        file_path,
    ]
    blint_output = subprocess.run(blint_command, cwd=WRAPDB_LOCATION, check=False)

    if DEBUG_MODE:
        print(blint_output.stdout)
        print(blint_output.stderr)


def get_blint_file(project_name):
    # run after blint was running
    blint_file = BOM_LOCATION / project_name / ".json"
    blint_str = None
    with open(blint_file, "r") as f:
        blint_str = f.read()
    return blint_str


def get_blint_internal_functions_exe(file_path):
    # here the file path is relative, we make it complete

    run_blint_on_file(file_path)
    blint_file = Path(f"{str(file_path)}.json")

    if_string = get_properties_internal("internal:functions", blint_file)
    return if_string.split(DELIMETER_BOM)
