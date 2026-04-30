# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import traceback
from dataclasses import dataclass
from pathlib import Path
from sqlite3 import OperationalError
from typing import Any

from blint_db import logger
from blint_db.handlers.language_handlers.conan_handler import (
    ConanProjectSpec,
    conan_cache_path,
    conan_graph_info,
    conan_install,
    conan_package_roots,
    conan_project_root,
    conan_remote_metadata,
    find_conan_artifacts_from_roots,
    parse_conan_reference,
)
from blint_db.ingest import ingest_binary_file


@dataclass(frozen=True, slots=True)
class ConanBuildResult:
    spec: ConanProjectSpec
    project_purl: str
    project_metadata: dict[str, Any]
    build_metadata: dict[str, Any]
    artifacts: list[str]
    build_root: Path
    deploy_root: Path
    package_roots: list[Path]
    target_triplet: str | None
    target_os: str | None
    target_arch: str | None
    build_mode: str
    optimization: str | None
    strip_status: str = "unknown"


def _project_purl(spec: ConanProjectSpec) -> str:
    reference_parts = parse_conan_reference(spec.reference)
    purl = f"pkg:conan/{reference_parts['name']}"
    if reference_parts.get("version"):
        purl += f"@{reference_parts['version']}"
    qualifiers = []
    if reference_parts.get("user"):
        qualifiers.append(f"user={reference_parts['user']}")
    if reference_parts.get("channel"):
        qualifiers.append(f"channel={reference_parts['channel']}")
    if spec.configuration:
        qualifiers.append(f"configuration={spec.configuration}")
    if qualifiers:
        purl += f"?{'&'.join(qualifiers)}"
    return purl


def _graph_nodes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    graph = payload.get("graph") or payload
    nodes = graph.get("nodes") or []
    if isinstance(nodes, dict):
        return [node for node in nodes.values() if isinstance(node, dict)]
    if isinstance(nodes, list):
        return [node for node in nodes if isinstance(node, dict)]
    return []


def _matching_nodes(
    payload: dict[str, Any], spec: ConanProjectSpec
) -> list[dict[str, Any]]:
    normalized_reference = spec.reference.split("#", 1)[0]
    return [
        node
        for node in _graph_nodes(payload)
        if (node.get("ref") or node.get("reference") or "").split("#", 1)[0]
        == normalized_reference
    ]


def _node_summary(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": node.get("id"),
        "ref": node.get("ref") or node.get("reference"),
        "package_id": node.get("package_id"),
        "recipe_revision": node.get("rrev") or node.get("recipe_revision"),
        "package_revision": node.get("prev") or node.get("package_revision"),
        "package_type": node.get("package_type"),
        "binary": node.get("binary"),
        "package_folder": node.get("package_folder")
        or (node.get("package") or {}).get("folder")
        or (node.get("folders") or {}).get("package_folder"),
        "settings": node.get("settings"),
        "options": node.get("options"),
        "conf": node.get("conf"),
        "homepage": node.get("homepage"),
        "license": node.get("license"),
        "description": node.get("description"),
        "topics": node.get("topics"),
    }


def _primary_node(
    graph_payload: dict[str, Any], spec: ConanProjectSpec
) -> dict[str, Any]:
    matching = _matching_nodes(graph_payload, spec)
    if matching:
        return matching[0]
    return {}


def _project_metadata(
    spec: ConanProjectSpec, graph_payload: dict[str, Any]
) -> dict[str, Any]:
    node = _primary_node(graph_payload, spec)
    reference_parts = parse_conan_reference(spec.reference)
    metadata = {
        "name": reference_parts["name"],
        "version": reference_parts.get("version"),
        "user": reference_parts.get("user"),
        "channel": reference_parts.get("channel"),
        "package_type": spec.package_type or node.get("package_type"),
        "description": node.get("description"),
        "homepage": node.get("homepage"),
        "license": node.get("license"),
        "topics": node.get("topics"),
        "configuration": spec.configuration,
        "notes": spec.notes,
    }
    return {
        key: value for key, value in metadata.items() if value not in (None, [], {})
    }


def _effective_target_os(spec: ConanProjectSpec) -> str | None:
    for key, value in spec.settings:
        if key == "os":
            return value
    return spec.target_os


def _effective_target_arch(spec: ConanProjectSpec) -> str | None:
    for key, value in spec.settings:
        if key == "arch":
            return value
    return spec.target_arch


def _target_triplet(spec: ConanProjectSpec) -> str | None:
    target_arch = _effective_target_arch(spec)
    target_os = _effective_target_os(spec)
    if not target_arch or not target_os:
        return None
    return f"{target_arch}-{target_os}-conan"


def build_conan_project(spec: ConanProjectSpec) -> ConanBuildResult:
    build_root = conan_project_root(spec)
    build_root.mkdir(parents=True, exist_ok=True)
    graph_payload = conan_graph_info(spec, build_root=build_root)
    install_payload = conan_install(spec, build_root=build_root)
    deploy_root = build_root / "deploy"
    package_roots = conan_package_roots(install_payload or graph_payload, spec=spec)
    roots_to_scan: list[Path] = []
    if deploy_root.exists():
        roots_to_scan.append(deploy_root)
    roots_to_scan.extend(package_roots)
    artifacts = find_conan_artifacts_from_roots(
        [str(path) for path in roots_to_scan],
        artifact_roots=spec.artifact_roots,
    )
    target_os = _effective_target_os(spec)
    target_arch = _effective_target_arch(spec)
    remote = conan_remote_metadata(build_root)
    matching_nodes = _matching_nodes(graph_payload or install_payload, spec)
    build_metadata = {
        "reference": spec.reference,
        "selector": spec.selector,
        "configuration": spec.configuration,
        "source": spec.source,
        "package_type": spec.package_type,
        "shared": spec.shared,
        "build_type": spec.build_type,
        "target_os": target_os,
        "target_arch": target_arch,
        "target_triplet": _target_triplet(spec),
        "settings": dict(spec.settings),
        "options": dict(spec.options),
        "conf": dict(spec.conf),
        "artifact_roots": list(spec.artifact_roots),
        "deploy_root": str(deploy_root),
        "package_roots": [str(path) for path in package_roots],
        "conan_cache_path": conan_cache_path(build_root),
        "conan_remote": remote,
        "graph_nodes": [_node_summary(node) for node in matching_nodes],
        "graph_info": graph_payload,
        "install_result": install_payload,
        "artifacts": artifacts,
        "notes": spec.notes,
    }
    return ConanBuildResult(
        spec=spec,
        project_purl=_project_purl(spec),
        project_metadata=_project_metadata(spec, graph_payload or install_payload),
        build_metadata=build_metadata,
        artifacts=artifacts,
        build_root=build_root,
        deploy_root=deploy_root,
        package_roots=package_roots,
        target_triplet=_target_triplet(spec),
        target_os=target_os,
        target_arch=target_arch,
        build_mode=spec.build_type,
        optimization=(spec.build_type or "").lower() if spec.build_type else None,
    )


def add_project_conan_db(
    project_spec: ConanProjectSpec,
    db_file: str | None = None,
    disassemble: bool = False,
):
    build_result = build_conan_project(project_spec)
    relative_to = (
        build_result.deploy_root
        if build_result.deploy_root.exists()
        else build_result.build_root
    )
    for artifact_path in build_result.artifacts:
        try:
            ingest_binary_file(
                artifact_path,
                db_file=db_file,
                project_name=project_spec.name,
                project_purl=build_result.project_purl,
                ecosystem="conan",
                project_metadata=build_result.project_metadata,
                build_system="conan",
                target_os=build_result.target_os,
                target_arch=build_result.target_arch,
                target_triplet=build_result.target_triplet,
                build_mode=build_result.build_mode,
                optimization=build_result.optimization,
                strip_status=build_result.strip_status,
                build_metadata=build_result.build_metadata,
                relative_to=relative_to,
                disassemble=disassemble,
            )
        except (RuntimeError, FileNotFoundError) as exc:
            logger.info("error encountered with %s", project_spec.selector)
            logger.error(exc)
            logger.error(traceback.format_exc())
    return build_result.artifacts


def mt_conan_blint_db_build(
    project_spec: ConanProjectSpec,
    db_file: str | None = None,
    disassemble: bool = False,
):
    logger.debug("Running Conan package %s", project_spec.selector)
    try:
        return add_project_conan_db(
            project_spec,
            db_file=db_file,
            disassemble=disassemble,
        )
    except (OperationalError, RuntimeError) as exc:
        logger.info("error encountered with %s", project_spec.selector)
        logger.error(exc)
        logger.error(traceback.format_exc())
        return []
