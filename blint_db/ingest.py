from __future__ import annotations

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import json
from pathlib import Path
from typing import Any

from blint_db.handlers.blint_handler import (
    collect_blint_metadata,
    load_blint_metadata,
    relative_binary_path,
    summarize_binary_metadata,
)
from blint_db.handlers.callgraph_handler import (
    extract_binary_callgraph,
    extract_source_callgraph,
)
from blint_db.handlers.sqlite_handler import (
    add_binary,
    add_build,
    create_database,
    get_connection,
    replace_binary_dependencies,
    replace_binary_function_fingerprints,
    replace_binary_symbols,
    replace_callgraph_edges,
    replace_callgraph_nodes,
    update_binary_statistics,
    upsert_project,
    upsert_source_graph,
)


def _load_optional_json_file(file_path: str | None):
    if not file_path:
        return None
    with open(file_path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _resolve_strip_status(strip_status: str | None):
    if strip_status == "stripped":
        return True
    if strip_status == "unstripped":
        return False
    return None


def ingest_metadata(
    *,
    metadata: dict[str, Any],
    db_file: str | None = None,
    project_name: str,
    project_purl: str | None = None,
    ecosystem: str | None = None,
    project_metadata=None,
    source_sbom=None,
    build_system: str = "manual",
    target_os: str | None = None,
    target_arch: str | None = None,
    target_triplet: str | None = None,
    build_mode: str | None = None,
    optimization: str | None = None,
    is_stripped=None,
    build_metadata=None,
    binary_file_path: str | None = None,
    relative_to: str | None = None,
) -> dict[str, Any]:
    create_database(db_file)
    binary_path = binary_file_path or metadata.get("file_path") or metadata.get("name")
    summarized = summarize_binary_metadata(metadata)
    summary = summarized["summary"]
    if binary_path:
        summary["file_path"] = str(binary_path)
    if not target_os:
        target_os = (
            build_metadata.get("target_os")
            if isinstance(build_metadata, dict)
            else None
        )
    if not target_arch:
        target_arch = (
            build_metadata.get("target_arch")
            if isinstance(build_metadata, dict)
            else None
        )
    if is_stripped is None:
        is_stripped = (metadata.get("security_properties") or {}).get("stripped")
    with get_connection(db_file) as connection:
        project_id = upsert_project(
            connection,
            project_name,
            purl=project_purl,
            ecosystem=ecosystem,
            metadata=project_metadata,
            source_sbom=source_sbom,
        )
        build_id = add_build(
            connection,
            project_id,
            build_system=build_system,
            target_os=target_os,
            target_arch=target_arch,
            target_triplet=target_triplet,
            llvm_target_tuple=metadata.get("llvm_target_tuple"),
            build_mode=build_mode,
            optimization=optimization,
            is_stripped=is_stripped,
            metadata=build_metadata,
        )
        binary_id = add_binary(
            connection,
            build_id,
            binary_path or project_name,
            relative_path=relative_binary_path(binary_path, relative_to)
            if binary_path
            else None,
            metadata=summary,
        )
        replace_binary_symbols(connection, binary_id, summarized["symbols"])
        replace_binary_dependencies(connection, binary_id, summarized["dependencies"])
        replace_binary_function_fingerprints(
            connection,
            binary_id,
            summarized["function_fingerprints"],
        )
        if metadata.get("callgraph"):
            binary_graph = extract_binary_callgraph(metadata)
            replace_callgraph_nodes(
                connection, "binary", binary_id, binary_graph["nodes"]
            )
            replace_callgraph_edges(
                connection, "binary", binary_id, binary_graph["edges"]
            )
        update_binary_statistics(connection, binary_id)
    return {
        "project_id": project_id,
        "build_id": build_id,
        "binary_id": binary_id,
        "binary_path": binary_path,
    }


def ingest_binary_file(
    binary_file_path: str,
    *,
    db_file: str | None = None,
    project_name: str,
    project_purl: str | None = None,
    ecosystem: str | None = None,
    project_metadata=None,
    source_sbom=None,
    build_system: str = "manual",
    target_os: str | None = None,
    target_arch: str | None = None,
    target_triplet: str | None = None,
    build_mode: str | None = None,
    optimization: str | None = None,
    strip_status: str | None = None,
    build_metadata=None,
    relative_to: str | None = None,
    disassemble: bool = False,
) -> dict[str, Any]:
    metadata = collect_blint_metadata(binary_file_path, disassemble=disassemble)
    return ingest_metadata(
        metadata=metadata,
        db_file=db_file,
        project_name=project_name,
        project_purl=project_purl,
        ecosystem=ecosystem,
        project_metadata=project_metadata,
        source_sbom=source_sbom,
        build_system=build_system,
        target_os=target_os,
        target_arch=target_arch,
        target_triplet=target_triplet,
        build_mode=build_mode,
        optimization=optimization,
        is_stripped=_resolve_strip_status(strip_status),
        build_metadata=build_metadata,
        binary_file_path=binary_file_path,
        relative_to=relative_to,
    )


def ingest_metadata_file(
    metadata_file: str,
    *,
    db_file: str | None = None,
    project_name: str,
    project_purl: str | None = None,
    ecosystem: str | None = None,
    project_metadata_file: str | None = None,
    source_sbom_file: str | None = None,
    build_system: str = "manual",
    target_os: str | None = None,
    target_arch: str | None = None,
    target_triplet: str | None = None,
    build_mode: str | None = None,
    optimization: str | None = None,
    strip_status: str | None = None,
    build_metadata=None,
    binary_file_path: str | None = None,
    relative_to: str | None = None,
) -> dict[str, Any]:
    metadata = load_blint_metadata(metadata_file)
    return ingest_metadata(
        metadata=metadata,
        db_file=db_file,
        project_name=project_name,
        project_purl=project_purl,
        ecosystem=ecosystem,
        project_metadata=_load_optional_json_file(project_metadata_file),
        source_sbom=_load_optional_json_file(source_sbom_file),
        build_system=build_system,
        target_os=target_os,
        target_arch=target_arch,
        target_triplet=target_triplet,
        build_mode=build_mode,
        optimization=optimization,
        is_stripped=_resolve_strip_status(strip_status),
        build_metadata=build_metadata,
        binary_file_path=binary_file_path,
        relative_to=relative_to,
    )


def ingest_source_callgraph(
    *,
    source_callgraph: dict[str, Any],
    source_key: str,
    db_file: str | None = None,
    project_id: int | None = None,
    name: str | None = None,
    purl: str | None = None,
    tool: str | None = None,
    tool_schema_version: str | None = None,
    metadata=None,
) -> dict[str, Any]:
    """Register a source callgraph and store its canonical nodes and edges.

    The source graph becomes part of the corpus that an unknown binary can be
    matched against via
    :func:`blint_db.handlers.sqlite_handler.match_binary_against_source_corpus`.

    Args:
        source_callgraph: Parsed source-analysis callgraph JSON.
        source_key: Stable identifier for this analysis; re-ingesting updates it.
        db_file: Optional database path override.
        project_id: Optional owning project to associate the graph with.
        name: Human-readable graph name.
        purl: Package URL the source graph belongs to.
        tool: Name of the source analyzer that produced the callgraph.
        tool_schema_version: Schema version reported by the analyzer.
        metadata: Optional extra metadata to persist.

    Returns:
        A dict with the ``source_graph_id`` and node/edge counts.
    """
    create_database(db_file)
    graph = extract_source_callgraph(source_callgraph)
    with get_connection(db_file) as connection:
        source_graph_id = upsert_source_graph(
            connection,
            source_key=source_key,
            project_id=project_id,
            name=name,
            purl=purl,
            tool=tool or (source_callgraph.get("tool") or {}).get("name"),
            tool_schema_version=tool_schema_version
            or source_callgraph.get("schema_version"),
            node_count=graph["node_count"],
            edge_count=graph["edge_count"],
            metadata=metadata,
        )
        replace_callgraph_nodes(connection, "source", source_graph_id, graph["nodes"])
        replace_callgraph_edges(connection, "source", source_graph_id, graph["edges"])
    return {
        "source_graph_id": source_graph_id,
        "node_count": graph["node_count"],
        "edge_count": graph["edge_count"],
    }


def infer_project_name(
    binary_file_path: str | None, metadata_file: str | None = None
) -> str:
    candidate = binary_file_path or metadata_file or "blint-binary"
    return Path(candidate).stem
