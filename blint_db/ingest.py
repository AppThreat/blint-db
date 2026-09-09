from __future__ import annotations

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import json
import os
import tempfile
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
    replace_binary_abi_requirements,
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
    archive_name: str | None = None,
) -> dict[str, Any]:
    create_database(db_file)
    binary_path = binary_file_path or metadata.get("file_path") or metadata.get("name")
    summarized = summarize_binary_metadata(metadata)
    summary = summarized["summary"]
    if binary_path:
        summary["file_path"] = str(binary_path)
    if archive_name:
        summary["archive_name"] = archive_name
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
        replace_binary_abi_requirements(
            connection,
            binary_id,
            summarized.get("abi_requirements") or [],
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


# Windows path separators must not smuggle a directory name into the member
# name; members are stored with a plain basename.
def extract_archive_members(
    archive_file_path: str | os.PathLike,
) -> list[dict[str, Any]]:
    """Return the object-file members of a static archive (``.a``/``.lib``).

    Each entry carries ``name`` (a plain basename) and ``data`` (the raw member
    bytes). Symbol-index members such as ``__.SYMDEF`` and the long-name
    members are skipped: they are archive bookkeeping, not compilable objects.
    """
    import ar

    members: list[dict[str, Any]] = []
    with open(archive_file_path, "rb") as handle:
        archive = ar.Archive(handle)
        for member in archive:
            name = os.path.basename(str(member.name).replace("\\", "/"))
            if not name or not name.lower().endswith((".o", ".obj")):
                continue
            data = member.get_stream(handle).read(member.size)
            if data:
                members.append({"name": name, "data": data})
    return members


def _is_macho_object_file(member_path: str) -> bool:
    """Whether the file is a relocatable Mach-O object (MH_OBJECT)."""
    import lief

    try:
        parsed = lief.MachO.parse(member_path)
        binary = parsed.at(0)
        return binary.header.file_type == lief.MachO.Header.FILE_TYPE.OBJECT
    except Exception:  # pylint: disable=broad-exception-caught
        return False


def _macho_text_range(member_path: str) -> tuple[int, int] | None:
    """Return the (start, end) byte range of the ``__TEXT,__text`` section."""
    import lief

    try:
        parsed = lief.MachO.parse(member_path)
        binary = parsed.at(0)
        for section in binary.sections:
            if (
                str(getattr(section, "segment_name", "")) == "__TEXT"
                and str(section.name) == "__text"
            ):
                start = int(section.virtual_address)
                return start, start + int(section.size)
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    return None


def _seed_object_file_functions(
    metadata: dict[str, Any], member_path: str
) -> bool:
    """Seed ``metadata["functions"]`` from symtab for Mach-O object members.

    Returns True when seeds were written. lief's Mach-O function list is built
    from LC_FUNCTION_STARTS and unwind data, neither of which exists in a
    relocatable object, and what little prologue scanning finds is a handful
    of local labels (an 81-symbol lapi.o discovered 7). The symbol table does
    carry every text symbol, so a member whose Mach-O file type is MH_OBJECT
    has its function list replaced by the defined section symbols inside
    ``__TEXT,__text`` -- always, including over any partial list parse left
    behind. Linked Mach-O images, ELF and PE members are left untouched.
    """
    if str(metadata.get("binary_type")) != "MachO":
        return False
    symtab = metadata.get("symtab_symbols") or []
    if not symtab:
        return False
    if not _is_macho_object_file(member_path):
        return False
    text_range = _macho_text_range(member_path)
    if not text_range:
        return False

    def _sym_addr(symbol: dict) -> int | None:
        try:
            return int(str(symbol.get("address")), 16)
        except (TypeError, ValueError):
            return None

    text_start, text_end = text_range
    in_text = [
        symbol
        for symbol in symtab
        if str(symbol.get("type")) == "TYPE.SECTION"
        and (addr := _sym_addr(symbol)) is not None
        and text_start <= addr < text_end
    ]
    if not in_text:
        return False
    in_text.sort(key=_sym_addr)
    functions = []
    for index, symbol in enumerate(in_text):
        start = _sym_addr(symbol) or 0
        next_addr = _sym_addr(in_text[index + 1]) if index + 1 < len(in_text) else None
        # No symbol sizes in a Mach-O symtab: bound each seed by the next
        # text symbol. The disassembler re-derives real function boundaries
        # from the instruction stream; the size only scopes the byte read.
        end = next_addr if next_addr else min(text_end, start + 4096)
        functions.append(
            {
                "index": index,
                "name": symbol.get("name"),
                "address": symbol.get("address"),
                "size": max(4, end - start),
                "flags": None,
            }
        )
    metadata["functions"] = functions
    return True


def _disassemble_member_metadata(metadata: dict[str, Any], member_path: str) -> None:
    """Disassemble a member whose function list was seeded post-parse.

    ``collect_blint_metadata(disassemble=True)`` runs disassembly inside
    blint's parse, before the object-file seed exists — so for seeded members
    the disassembly has to be driven here. The disassembler reads function
    bytes through the lief object, which blint does not expose on its metadata,
    hence the format-specific re-parse (mirroring blint's own dispatch).
    """
    import lief

    from blint.lib.binary import attach_function_hashes
    from blint.lib.disassembler import disassemble_functions

    binary_type = str(metadata.get("binary_type"))
    try:
        if binary_type == "ELF":
            parsed = lief.ELF.parse(member_path)
            parsed_obj = parsed.at(0) if len(parsed) else None
        elif binary_type == "MachO":
            parsed_obj = lief.MachO.parse(member_path).at(0)
        elif binary_type == "PE":
            parsed_obj = lief.PE.parse(member_path)
        else:
            parsed_obj = None
    except Exception:  # pylint: disable=broad-exception-caught
        parsed_obj = None
    if parsed_obj is None:
        return
    disassembled = disassemble_functions(parsed_obj, metadata)
    if not disassembled:
        return
    metadata["disassembled_functions"] = disassembled
    attach_function_hashes(disassembled)


def ingest_archive_members(
    archive_file_path: str,
    *,
    db_file: str | None = None,
    project_name: str,
    project_purl: str | None = None,
    ecosystem: str | None = None,
    build_system: str = "manual",
    strip_status: str | None = None,
    disassemble: bool = False,
    archive_name: str | None = None,
) -> list[dict[str, Any]]:
    """Ingest every object member of a static archive as its own binary row.

    Member rows carry ``archive_name`` so consumers can group function-hash
    evidence at member granularity (the unit a statically linked binary
    actually contains). Returns one result dict per ingested member.
    """
    results: list[dict[str, Any]] = []
    archive_name = archive_name or os.path.basename(archive_file_path)
    with tempfile.TemporaryDirectory(prefix="blintdb-members-") as temp_dir:
        for index, member in enumerate(extract_archive_members(archive_file_path)):
            member_path = os.path.join(temp_dir, f"{index:06d}_{member['name']}")
            with open(member_path, "wb") as member_handle:
                member_handle.write(member["data"])
            try:
                metadata = collect_blint_metadata(member_path, disassemble=disassemble)
            except Exception:  # pylint: disable=broad-exception-caught
                continue
            if not metadata:
                continue
            # Report the member's own name, not the temporary file's index
            # prefix; the prefix only keeps same-named members from different
            # archives from colliding on disk.
            metadata["name"] = member["name"]
            if disassemble and _seed_object_file_functions(metadata, member_path):
                # Mach-O relocatable members discover almost nothing inside
                # blint's parse (lief builds its function list from
                # LC_FUNCTION_STARTS, absent in objects); re-disassemble
                # against the seeded symbol table instead.
                _disassemble_member_metadata(metadata, member_path)
            result = ingest_metadata(
                metadata=metadata,
                db_file=db_file,
                project_name=project_name,
                project_purl=project_purl,
                ecosystem=ecosystem,
                build_system=build_system,
                is_stripped=_resolve_strip_status(strip_status),
                binary_file_path=member_path,
                archive_name=archive_name,
            )
            result["member_name"] = member["name"]
            results.append(result)
    return results


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
