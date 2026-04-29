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


def add_project_cargo_db(
    project_spec: CargoProjectSpec,
    db_file: str | None = None,
    disassemble: bool = False,
):
    try:
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
    except RuntimeError as exc:
        logger.info(f"error encountered with {project_spec.selector}")
        logger.error(exc)
        logger.error(traceback.format_exc())
        return []
    return build_result.artifacts


def mt_cargo_blint_db_build(
    project_spec: CargoProjectSpec,
    db_file: str | None = None,
    disassemble: bool = False,
):
    logger.debug("Running cargo crate %s", project_spec.selector)
    try:
        return add_project_cargo_db(
            project_spec,
            db_file=db_file,
            disassemble=disassemble,
        )
    except OperationalError as exc:
        logger.info(f"error encountered with {project_spec.selector}")
        logger.error(exc)
        logger.error(traceback.format_exc())
        return []
