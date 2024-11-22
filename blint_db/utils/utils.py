# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

from blint_db import DEBUG_MODE, WRAPDB_LOCATION, logger


def subprocess_run_debug(setup_run, project_name):
    if DEBUG_MODE:
        print(setup_run.stdout)
        print(setup_run.stderr)
        if setup_run.stderr:
            logger.error(
                f"{project_name} failed to SETUP {WRAPDB_LOCATION / 'build' / project_name}"
            )
            logger.error(f"{project_name}: {setup_run.stdout.decode('ascii')}")
