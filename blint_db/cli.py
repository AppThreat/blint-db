# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import argparse
import os
import shutil
import sqlite3
from concurrent import futures
from pathlib import Path
from typing import List

from blint_db import BLINTDB_LOCATION, COMMON_CONNECTION
from blint_db.handlers.language_handlers.vcpkg_handler import (
    get_vcpkg_projects, remove_vcpkg_project)
from blint_db.handlers.language_handlers.wrapdb_handler import \
    get_wrapdb_projects
from blint_db.handlers.sqlite_handler import (clear_sqlite_database,
                                              create_database)
from blint_db.projects_compiler.meson import mt_meson_blint_db_build
from blint_db.projects_compiler.vcpkg import mt_vcpkg_blint_db_build


def arguments_parser():
    parser = argparse.ArgumentParser(
        prog="blint_db", description="Stores Symbols for binaries"
    )
    parser.add_argument(
        "-c",
        "--cdxgen-bom",
        dest="cdxgen_bom",
        help="Path to the CDXGEN bom file (NOT IMPLEMENTED)",
    )
    parser.add_argument(
        "-cs",
        "--add-cdxgen-db",
        dest="add_cdxgen_db",
        action="store_true",
        help="This flag allows to add Cdxgen BOM to Database",
    )
    parser.add_argument(
        "-b",
        "--blint-sbom",
        dest="blintsbom",
        help="Path to the Blint SBOM for a binary (NOT IMPLEMENTED)",
    )
    parser.add_argument(
        "-bs",
        "--add-blint-db",
        dest="add_blint_db",
        action="store_true",
        help="This flag allows to add blint SBOM to Database",
    )
    parser.add_argument(
        "-Z1",
        "--meson-blintdb",
        dest="meson",
        action="store_true",
        help="This flag starts the automatic blintdb build using wrapdb packages",
    )
    parser.add_argument(
        "-Z2",
        "--vcpkg-blintdb",
        dest="vcpkg",
        action="store_true",
        help="This flag starts the automatic blintdb build using vcpkg packages",
    )
    parser.add_argument(
        "--clean-start",
        dest="clean",
        action="store_true",
        help="Resets the database before starting a new build",
    )
    parser.add_argument(
        "-f",
        "--few-packages",
        dest="test_mode",
        action="store_true",
        help="Set pkg managers to build fewer projects, helpful for debugging",
    )
    parser.add_argument(
        "-s",
        "--select-project",
        nargs="+",
        dest="sel_project",
        help="List of project you would like to compile helpful for debugging",
    )

    return parser.parse_args()


def reset_and_backup():
    if COMMON_CONNECTION:
        if os.path.exists(BLINTDB_LOCATION) and os.path.isfile(BLINTDB_LOCATION):
            os.remove(BLINTDB_LOCATION)
        COMMON_CONNECTION.execute(f"vacuum main into '{BLINTDB_LOCATION}'")


def meson_add_blint_bom_process(test_mode=False, sel_project: List = None):
    projects_list = get_wrapdb_projects()
    if test_mode:
        projects_list = projects_list[:10]
    if sel_project:
        projects_list = sel_project

    # build the projects single threaded
    # st_meson_blint_db_build(projects_list)

    with futures.ProcessPoolExecutor(max_workers=1) as executor:
        for project_name, executables in zip(
            projects_list, executor.map(mt_meson_blint_db_build, projects_list)
        ):
            print(f"Ran complete for {project_name} and we found {len(executables)}")


def remove_temp_ar():
    """
    Removes `ar-temp-########` files created by blint extract-ar function,
    after we have completed our tasks.
    """

    try:
        for dirname in Path("/tmp").glob("ar-temp-*"):
            try:
                shutil.rmtree(dirname)
            except OSError as e:
                print(f"Error deleting file {dirname}: {e}")
    except Exception as e:
        print(f"Error during cleanup: {e}")


def vcpkg_add_blint_bom_process(test_mode=False, sel_project: List = None):
    projects_list = get_vcpkg_projects()
    if test_mode:
        projects_list = projects_list[:10]
    if sel_project:
        projects_list = sel_project
    count = 0
    for project_name in projects_list:
        executables = mt_vcpkg_blint_db_build(project_name)
        print(f"Ran complete for {project_name} and we found {len(executables)}")
        remove_vcpkg_project(project_name)
        count += 1
        if count == 100:
            reset_and_backup()
            remove_temp_ar()
            count = 0


def main():

    args = vars(arguments_parser())

    if args["clean"]:
        clear_sqlite_database()
        create_database()

    if args["meson"]:
        meson_add_blint_bom_process(args["test_mode"], args["sel_project"])

    if args["vcpkg"]:
        vcpkg_add_blint_bom_process(args["test_mode"], args["sel_project"])

    if COMMON_CONNECTION:
        reset_and_backup()
        print("Build Completed Saved Database")


if __name__ == "__main__":
    main()
