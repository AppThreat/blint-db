from __future__ import annotations

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import traceback
from sqlite3 import OperationalError

from blint_db import logger
from blint_db.handlers.language_handlers.cargo_handler import (
    CargoProjectSpec,
    build_cargo_project,
)
from blint_db.handlers.language_handlers.rusi_handler import run_rusi_callgraph
from blint_db.ingest import ingest_binary_file, ingest_source_callgraph
from blint_db.utils.provenance import build_failure_record, build_project_outcome


def _record_outcome(project_outcomes, **kwargs):
    if project_outcomes is not None:
        project_outcomes.append(build_project_outcome(**kwargs))


def _ingest_cargo_source_callgraph(
    project_spec: CargoProjectSpec,
    build_result,
    *,
    db_file: str | None,
    project_id: int | None,
    rusi_command: str | None,
):
    """Run rusi over the crate source and ingest the resulting source callgraph.

    Returns the ingest result dict, or ``None`` when rusi is not configured or
    produced no usable callgraph. Failures are logged and swallowed so a single
    crate cannot abort a corpus build.
    """
    source_callgraph = run_rusi_callgraph(
        build_result.source_root,
        rusi_command=rusi_command,
        work_dir=build_result.source_root,
    )
    if not source_callgraph:
        return None
    return ingest_source_callgraph(
        source_callgraph=source_callgraph,
        source_key=build_result.project_purl,
        db_file=db_file,
        project_id=project_id,
        name=project_spec.crate,
        purl=build_result.project_purl,
        tool="rusi",
    )


def add_project_cargo_db(
    project_spec: CargoProjectSpec,
    db_file: str | None = None,
    disassemble: bool = False,
    with_source_callgraph: bool = False,
    rusi_command: str | None = None,
):
    build_result = build_cargo_project(project_spec)
    project_id = None
    for artifact_path in build_result.artifacts:
        try:
            ingest_result = ingest_binary_file(
                artifact_path,
                db_file=db_file,
                project_name=project_spec.crate,
                project_purl=build_result.project_purl,
                ecosystem="cargo",
                project_metadata=build_result.project_metadata,
                build_system="cargo",
                target_os=build_result.target_os,
                target_arch=build_result.target_arch,
                target_triplet=build_result.target_triplet,
                build_mode=build_result.build_mode,
                optimization=build_result.optimization,
                strip_status=build_result.strip_status,
                build_metadata=build_result.build_metadata,
                relative_to=build_result.target_dir,
                disassemble=disassemble,
            )
            if project_id is None and isinstance(ingest_result, dict):
                project_id = ingest_result.get("project_id")
        except (RuntimeError, FileNotFoundError) as exc:
            logger.info(f"error encountered with {project_spec.selector}")
            logger.error(exc)
    if with_source_callgraph:
        try:
            _ingest_cargo_source_callgraph(
                project_spec,
                build_result,
                db_file=db_file,
                project_id=project_id,
                rusi_command=rusi_command,
            )
        except (RuntimeError, FileNotFoundError, OSError) as exc:
            logger.info(f"source callgraph ingest failed for {project_spec.selector}")
            logger.error(exc)
    return build_result.artifacts


def mt_cargo_blint_db_build(
    project_spec: CargoProjectSpec,
    db_file: str | None = None,
    disassemble: bool = False,
    project_outcomes=None,
    with_source_callgraph: bool = False,
    rusi_command: str | None = None,
):
    logger.debug("Running cargo crate %s", project_spec.selector)
    try:
        artifacts = add_project_cargo_db(
            project_spec,
            db_file=db_file,
            disassemble=disassemble,
            with_source_callgraph=with_source_callgraph,
            rusi_command=rusi_command,
        )
        failure = None
        status = "success"
        if not artifacts:
            status = "no_artifacts"
            failure = build_failure_record(
                stage="artifact-discovery",
                message=f"No cargo artifacts were retained for {project_spec.selector}",
            )
        _record_outcome(
            project_outcomes,
            selector=project_spec.selector,
            project_name=project_spec.crate,
            ecosystem="cargo",
            build_system="cargo",
            status=status,
            artifact_count=len(artifacts),
            failure=failure,
        )
        return artifacts
    except (OperationalError, RuntimeError) as exc:
        logger.info(f"error encountered with {project_spec.selector}")
        logger.error(exc)
        _record_outcome(
            project_outcomes,
            selector=project_spec.selector,
            project_name=project_spec.crate,
            ecosystem="cargo",
            build_system="cargo",
            status="build_failed" if isinstance(exc, RuntimeError) else "ingest_failed",
            artifact_count=0,
            failure=build_failure_record(
                stage="build" if isinstance(exc, RuntimeError) else "database",
                message=str(exc),
                exception=exc,
            ),
        )
        return []
