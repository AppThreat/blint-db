# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
import json
import os
import subprocess
import traceback
from sqlite3 import OperationalError

from blint_db import (
    ANDROID_NDK_HOME,
    DEBUG_MODE,
    SYSTEM,
    ARCH,
    VCPKG_COMMIT_HASH,
    VCPKG_DEFAULT_TRIPLET,
    VCPKG_LOCATION,
    VCPKG_OVERLAY_TRIPLETS,
    VCPKG_URL,
    logger,
)
from blint_db.handlers.git_handler import git_checkout_commit, git_clone
from blint_db.handlers.language_handlers.vcpkg_handler import (
    find_vcpkg_executables,
    vcpkg_build,
)
from blint_db.ingest import ingest_archive_members, ingest_binary_file
from blint_db.utils.android import (
    is_android_triplet,
    read_ndk_revision,
    read_triplet_api_level,
    triplet_target_os_arch,
)
from blint_db.utils.provenance import build_failure_record, build_project_outcome


def _record_outcome(project_outcomes, **kwargs):
    if project_outcomes is not None:
        project_outcomes.append(build_project_outcome(**kwargs))


def git_clone_vcpkg():
    git_clone(VCPKG_URL, VCPKG_LOCATION)


def git_checkout_vcpkg_commit():
    git_checkout_commit(VCPKG_LOCATION, VCPKG_COMMIT_HASH)


def run_vcpkg_install_command():
    # Linux command
    install_command = ["bash", "bootstrap-vcpkg.sh"]
    install_run = subprocess.run(
        install_command,
        cwd=VCPKG_LOCATION,
        capture_output=True,
        check=False,
        encoding="utf-8",
    )
    if DEBUG_MODE:
        logger.debug(f"'bootstrap-vcpkg.sh: {install_run.stdout}")

    int_command = "./vcpkg integrate install".split(" ")
    int_run = subprocess.run(
        int_command,
        cwd=VCPKG_LOCATION,
        capture_output=True,
        check=False,
        encoding="utf-8",
    )
    if DEBUG_MODE:
        logger.debug(f"'vcpkg integrate install: {int_run.stdout}")


def exec_explorer(directory):
    """
    Walks through a directory and identifies executable files using the `file` command.

    Args:
      directory: The directory to search.

    Returns:
      A list of executable file paths.
    """
    executables = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            executables.append(file_path)
    return executables


def _port_version(vcpkg_metadata: dict) -> str | None:
    """The port's own version string, whichever schema field declares it.

    vcpkg ports carry their version as ``version``, ``version-string``,
    ``version-semver`` or ``version-date``; reading only the first lost the
    purl version for ports like aom that use ``version-semver``.
    """
    for key in ("version", "version-string", "version-semver", "version-date"):
        if vcpkg_metadata.get(key):
            return str(vcpkg_metadata[key])
    return None


def add_project_vcpkg_db(project_name, vcpkg_json, db_file=None, disassemble=False):
    purl = None
    metadata = None
    if vcpkg_json and os.path.exists(vcpkg_json):
        with open(vcpkg_json, encoding="utf-8") as fp:
            try:
                vcpkg_metadata = json.load(fp)
                version = _port_version(vcpkg_metadata)
                purl = (
                    f"pkg:generic/{vcpkg_metadata['name']}@{version}"
                    if version
                    else f"pkg:generic/{vcpkg_metadata['name']}"
                )
                description = vcpkg_metadata.get("description")
                metadata = {
                    "description": description,
                    "dependencies": vcpkg_metadata.get("dependencies"),
                }
            except json.JSONDecodeError as e:
                logger.error(e)
    build_result = vcpkg_build(project_name)
    if getattr(build_result, "returncode", 1) != 0:
        raise RuntimeError(f"vcpkg build failed for {project_name}")
    # Android cross builds: the Builds rows must describe the *target*, not
    # the machine that compiled it, and carry the NDK revision (from
    # ANDROID_NDK_HOME/source.properties) and the API level the triplet's
    # VCPKG_CMAKE_SYSTEM_VERSION selects. Host triplets keep host-derived
    # target fields, as before.
    target_os, target_arch = triplet_target_os_arch(
        VCPKG_DEFAULT_TRIPLET, host_os=SYSTEM, host_arch=ARCH
    )
    build_metadata: dict = {}
    if vcpkg_json:
        build_metadata["vcpkg_json"] = str(vcpkg_json)
    if is_android_triplet(VCPKG_DEFAULT_TRIPLET):
        build_metadata["android"] = {
            "ndk_home": str(ANDROID_NDK_HOME) if ANDROID_NDK_HOME else None,
            "ndk_revision": read_ndk_revision(ANDROID_NDK_HOME),
            "api_level": read_triplet_api_level(
                VCPKG_DEFAULT_TRIPLET, VCPKG_LOCATION, VCPKG_OVERLAY_TRIPLETS
            ),
            "abi": VCPKG_DEFAULT_TRIPLET.removesuffix("-dynamic"),
        }
    execs = find_vcpkg_executables(project_name)
    for files in execs:
        try:
            ingest_binary_file(
                files,
                db_file=db_file,
                project_name=project_name,
                project_purl=purl,
                ecosystem="vcpkg",
                project_metadata=metadata,
                build_system="vcpkg",
                target_os=target_os,
                target_arch=target_arch,
                target_triplet=VCPKG_DEFAULT_TRIPLET,
                build_mode="debug+release",
                strip_status="unstripped",
                build_metadata=dict(build_metadata) or None,
                relative_to=VCPKG_LOCATION / "installed" / VCPKG_DEFAULT_TRIPLET,
                disassemble=disassemble,
            )
            # Static archives (the default for vcpkg's Android triplets, and
            # common for cross builds generally) parse to nothing as a whole:
            # lief does not read the ar container, so the whole-file row
            # carries no symbols. The object members are the queryable unit
            # (P4.3 member rows), so each archive is also ingested member by
            # member.
            if str(files).lower().endswith((".a", ".lib")):
                member_results = ingest_archive_members(
                    files,
                    db_file=db_file,
                    project_name=project_name,
                    project_purl=purl,
                    ecosystem="vcpkg",
                    build_system="vcpkg",
                    target_os=target_os,
                    target_arch=target_arch,
                    target_triplet=VCPKG_DEFAULT_TRIPLET,
                    build_mode="debug+release",
                    strip_status="unstripped",
                    build_metadata=dict(build_metadata) or None,
                    disassemble=disassemble,
                    archive_name=os.path.basename(files),
                )
                logger.debug(
                    "Ingested %d archive members for %s", len(member_results), files
                )
        except (RuntimeError, FileNotFoundError) as e:
            logger.info(f"error encountered with {project_name}")
            logger.error(e)
    return execs


def mt_vcpkg_blint_db_build(
    project_name,
    vcpkg_json,
    db_file=None,
    disassemble=False,
    project_outcomes=None,
):
    logger.debug(f"Running {project_name} with vcpkg {vcpkg_json}")
    try:
        execs = add_project_vcpkg_db(
            project_name,
            vcpkg_json,
            db_file=db_file,
            disassemble=disassemble,
        )
        failure = None
        status = "success"
        if not execs:
            status = "no_artifacts"
            failure = build_failure_record(
                stage="artifact-discovery",
                message=f"No vcpkg artifacts were retained for {project_name}",
            )
        _record_outcome(
            project_outcomes,
            selector=project_name,
            project_name=project_name,
            ecosystem="vcpkg",
            build_system="vcpkg",
            status=status,
            artifact_count=len(execs),
            failure=failure,
            details={"vcpkg_json": str(vcpkg_json)} if vcpkg_json else None,
        )
        return execs
    except (OperationalError, RuntimeError) as e:
        logger.info(f"error encountered with {project_name}")
        logger.error(e)
        _record_outcome(
            project_outcomes,
            selector=project_name,
            project_name=project_name,
            ecosystem="vcpkg",
            build_system="vcpkg",
            status="build_failed" if isinstance(e, RuntimeError) else "ingest_failed",
            artifact_count=0,
            failure=build_failure_record(
                stage="build" if isinstance(e, RuntimeError) else "database",
                message=str(e),
                exception=e,
            ),
            details={"vcpkg_json": str(vcpkg_json)} if vcpkg_json else None,
        )
        return []
