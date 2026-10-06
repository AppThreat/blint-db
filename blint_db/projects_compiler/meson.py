# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
import configparser
import json
import os
import shutil
import subprocess
import sys
import traceback
from sqlite3 import OperationalError

from blint_db import (
    ARCH,
    MESON_BUILD_TYPE,
    MESON_STRIP,
    SYSTEM,
    WRAPDB_COMMIT_HASH,
    WRAPDB_LOCATION,
    WRAPDB_URL,
    logger,
)
from blint_db.handlers.git_handler import git_checkout_commit, git_clone
from blint_db.handlers.language_handlers.meson_handler import (
    build_dir_for,
    find_meson_executables,
    meson_build,
)
from blint_db.ingest import ingest_binary_file
from blint_db.utils.provenance import build_failure_record, build_project_outcome


def _record_outcome(project_outcomes, **kwargs):
    if project_outcomes is not None:
        project_outcomes.append(build_project_outcome(**kwargs))


def _isolated_ingest_enabled() -> bool:
    return os.getenv("BLINT_DB_ISOLATED_INGEST", "1") != "0"


def _ingest_files_isolated(
    files,
    *,
    db_file,
    project_name,
    project_purl,
    ecosystem,
    project_metadata,
    build_system,
    target_os,
    target_arch,
    build_mode,
    strip_status,
    build_metadata,
    relative_to,
    disassemble,
):
    """Ingest files in a worker subprocess and log per-file errors.

    Parsing (with disassembly) peaks at hundreds of MB per large binary and
    the allocator retains those arenas, so a whole-corpus run ratchets RSS up
    until the OOM killer strikes. A worker per project bounds that peak to a
    single project; its exit returns the memory to the OS.
    """
    command = [
        sys.executable,
        "-m",
        "blint_db.projects_compiler.ingest_worker",
        "--project-name",
        project_name,
        "--build-system",
        build_system,
    ]
    if db_file:
        command += ["--db-file", str(db_file)]
    if project_purl:
        command += ["--project-purl", project_purl]
    if ecosystem:
        command += ["--ecosystem", ecosystem]
    if project_metadata:
        command += ["--project-metadata-json", json.dumps(project_metadata)]
    if target_os:
        command += ["--target-os", target_os]
    if target_arch:
        command += ["--target-arch", target_arch]
    if build_mode:
        command += ["--build-mode", build_mode]
    if strip_status:
        command += ["--strip-status", strip_status]
    if build_metadata:
        command += ["--build-metadata-json", json.dumps(build_metadata)]
    if relative_to:
        command += ["--relative-to", str(relative_to)]
    if disassemble:
        command.append("--disassemble")
    command += [str(f) for f in files]
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, check=False
        )
    except OSError as exc:
        raise RuntimeError(
            f"Failed to start isolated ingest worker for {project_name}: {exc}"
        ) from exc
    if proc.returncode != 0:
        raise RuntimeError(
            f"Isolated ingest worker failed for {project_name} with return code "
            f"{proc.returncode}: {proc.stderr.strip()[-2000:]}"
        )
    try:
        results = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Isolated ingest worker for {project_name} produced no parseable "
            f"result: {exc}"
        ) from exc
    for entry in results:
        if entry.get("status") == "error":
            logger.error(
                "error encountered with %s", f'{project_name}:{entry.get("file")}'
            )
            logger.error(entry.get("error"))


def git_clone_wrapdb():
    git_clone(WRAPDB_URL, WRAPDB_LOCATION)


def git_checkout_wrapdb_commit():
    git_checkout_commit(WRAPDB_LOCATION, WRAPDB_COMMIT_HASH)


def ensure_meson_installed():
    return shutil.which("meson") is not None


def add_project_meson_db(project_name, wrap_file, db_file=None, disassemble=False):
    purl = None
    metadata = None
    if wrap_file and os.path.exists(wrap_file):
        config = configparser.ConfigParser()
        try:
            config.read(wrap_file)
            source_hash = config["wrap-file"]["source_hash"]
            directory = config["wrap-file"]["directory"]
            name = directory
            version = None
            if "-" in name:
                tmp_a = name.split("-")
                if len(tmp_a) >= 2:
                    version = tmp_a[-1]
                    name = name.replace(f"-{version}", "")
            name_with_version = f"{name}@{version}" if version else name
            purl = f"pkg:generic/{name_with_version}?source_hash={source_hash}"
            metadata = {"source_url": config["wrap-file"]["source_url"]}
        except (
            configparser.NoSectionError,
            configparser.NoOptionError,
            configparser.InterpolationSyntaxError,
        ):
            logger.info(f"Unable to parse {wrap_file}")
            pass
        except Exception:
            pass
    build_result = meson_build(project_name)
    if getattr(build_result, "returncode", 1) != 0:
        raise RuntimeError(
            f"Meson build failed for {project_name} with return code {build_result.returncode}"
        )
    execs = find_meson_executables(project_name)
    if execs and _isolated_ingest_enabled():
        _ingest_files_isolated(
            execs,
            db_file=db_file,
            project_name=project_name,
            project_purl=purl,
            ecosystem="wrapdb",
            project_metadata=metadata,
            build_system="meson",
            target_os=SYSTEM,
            target_arch=ARCH,
            build_mode=MESON_BUILD_TYPE,
            strip_status="stripped" if MESON_STRIP else "unstripped",
            build_metadata={"wrap_file": str(wrap_file)} if wrap_file else None,
            relative_to=WRAPDB_LOCATION / "build" / project_name,
            disassemble=disassemble,
        )
    else:
        for files in execs:
            try:
                ingest_binary_file(
                    files,
                    db_file=db_file,
                    project_name=project_name,
                    project_purl=purl,
                    ecosystem="wrapdb",
                    project_metadata=metadata,
                    build_system="meson",
                    target_os=SYSTEM,
                    target_arch=ARCH,
                    build_mode=MESON_BUILD_TYPE,
                    strip_status="stripped" if MESON_STRIP else "unstripped",
                    build_metadata={"wrap_file": str(wrap_file)} if wrap_file else None,
                    relative_to=WRAPDB_LOCATION / "build" / project_name,
                    disassemble=disassemble,
                )
            except (RuntimeError, FileNotFoundError) as e:
                logger.info(f"error encountered with {project_name}")
                logger.error(e)
                logger.error(traceback.format_exc())
    return execs


def mt_meson_blint_db_build(
    project_name_wrap_tuple,
    db_file=None,
    disassemble=False,
    project_outcomes=None,
):
    project_name, wrap_file = project_name_wrap_tuple
    logger.debug(f"Running {project_name}")
    try:
        execs = add_project_meson_db(
            project_name,
            wrap_file,
            db_file=db_file,
            disassemble=disassemble,
        )
        failure = None
        status = "success"
        if not execs:
            status = "no_artifacts"
            failure = build_failure_record(
                stage="artifact-discovery",
                message=f"No Meson artifacts were retained for {project_name}",
            )
        _record_outcome(
            project_outcomes,
            selector=project_name,
            project_name=project_name,
            ecosystem="wrapdb",
            build_system="meson",
            status=status,
            artifact_count=len(execs),
            failure=failure,
            details={"wrap_file": str(wrap_file)} if wrap_file else None,
        )
    except RuntimeError as e:
        logger.info(f"error encountered with {project_name}")
        logger.error(e)
        meson_log_file = build_dir_for(project_name) / "meson-logs" / "meson-log.txt"
        if meson_log_file.exists():
            logger.error(f"Meson log for {project_name}: {meson_log_file}")
        _record_outcome(
            project_outcomes,
            selector=project_name,
            project_name=project_name,
            ecosystem="wrapdb",
            build_system="meson",
            status="build_failed",
            artifact_count=0,
            failure=build_failure_record(
                stage="build",
                message=str(e),
                exception=e,
            ),
            details={"wrap_file": str(wrap_file)} if wrap_file else None,
        )
        return []
    except OperationalError as e:
        logger.info(f"error encountered with {project_name}")
        logger.error(e)
        _record_outcome(
            project_outcomes,
            selector=project_name,
            project_name=project_name,
            ecosystem="wrapdb",
            build_system="meson",
            status="ingest_failed",
            artifact_count=0,
            failure=build_failure_record(
                stage="database",
                message=str(e),
                exception=e,
            ),
            details={"wrap_file": str(wrap_file)} if wrap_file else None,
        )
        return []
    return execs
