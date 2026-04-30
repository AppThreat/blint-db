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
from blint_db.ingest import ingest_binary_file
from blint_db.utils.provenance import build_failure_record, build_project_outcome


def _record_outcome(project_outcomes, **kwargs):
    if project_outcomes is not None:
        project_outcomes.append(build_project_outcome(**kwargs))


def add_project_cargo_db(
    project_spec: CargoProjectSpec,
    db_file: str | None = None,
    disassemble: bool = False,
):
    build_result = build_cargo_project(project_spec)
    for artifact_path in build_result.artifacts:
        try:
            ingest_binary_file(
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
        except (RuntimeError, FileNotFoundError) as exc:
            logger.info(f"error encountered with {project_spec.selector}")
            logger.error(exc)
            logger.error(traceback.format_exc())
    return build_result.artifacts


def mt_cargo_blint_db_build(
    project_spec: CargoProjectSpec,
    db_file: str | None = None,
    disassemble: bool = False,
    project_outcomes=None,
):
    logger.debug("Running cargo crate %s", project_spec.selector)
    try:
        artifacts = add_project_cargo_db(
            project_spec,
            db_file=db_file,
            disassemble=disassemble,
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
        logger.error(traceback.format_exc())
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
