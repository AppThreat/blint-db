# SPDX-FileCopyrightText: 2024 AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import subprocess

from blint_db import WRAPDB_LOCATION


class BaseHandler:
    strip = True

    def strip_executables(self, file_path, loc=WRAPDB_LOCATION):
        if self.strip:
            strip_command = f"strip --strip-all {file_path}".split(" ")
            subprocess.run(strip_command, cwd=loc, check=False)
