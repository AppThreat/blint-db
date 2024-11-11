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
from blint_db.projects_compiler.meson import mt_meson_blint_db_build, meson_add_blint_bom_process
from blint_db.projects_compiler.vcpkg import mt_vcpkg_blint_db_build, vcpkg_add_blint_bom_process


def arguments_parser():
    """
    Parse command-line arguments for the blint_db application.

    This function sets up an argument parser that allows users to specify various options for managing symbols in binaries.
    It provides flags for adding BOM files to the database, starting automatic builds, and configuring the build process.

    Returns:
        Namespace: An object containing the parsed command-line arguments.

    Args:
        -c, --cdxgen-bom: Path to the CDXGEN bom file (NOT IMPLEMENTED).
        -cs, --add-cdxgen-db: Flag to add Cdxgen BOM to the database.
        -b, --blint-sbom: Path to the Blint SBOM for a binary (NOT IMPLEMENTED).
        -bs, --add-blint-db: Flag to add Blint SBOM to the database.
        -Z1, --meson-blintdb: Flag to start automatic blintdb build using wrapdb packages.
        -Z2, --vcpkg-blintdb: Flag to start automatic blintdb build using vcpkg packages.
        --clean-start: Flag to reset the database before starting a new build.
        -f, --few-packages: Flag to set package managers to build fewer projects, helpful for debugging.
        -s, --select-project: List of projects to compile, helpful for debugging.
    """
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


def main():
    """
    Main entry point for the blint_db application.

    This function orchestrates the execution of the application based on the parsed command-line arguments.
    It handles database management, initiates build processes, and performs cleanup as specified by the user.

    Returns:
        None

    Args:
        None
    """

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
