from __future__ import annotations

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

from blint.lib.binary import parse
from blint_db.utils.json import make_json_safe, coerce_json_object, optional_json_object

SYMBOL_SOURCES = (
    "functions",
    "ctor_functions",
    "dtor_functions",
    "exception_functions",
    "unwind_functions",
    "exports",
    "imports",
    "symtab_symbols",
    "dynamic_symbols",
    "exceptions",
)
DISASSEMBLY_HASH_MODES = {"none", "assembly", "instruction", "both"}


def collect_blint_metadata(
    file_path: str | os.PathLike, *, disassemble: bool = False
) -> dict:
    return parse(str(file_path), disassemble=disassemble) or {}


def load_blint_metadata(metadata_file: str | os.PathLike) -> dict:
    with open(metadata_file, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _safe_int(value):
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_hash_mode(hash_mode: str = "both") -> str:
    normalized = (hash_mode or "both").strip().lower()
    if normalized not in DISASSEMBLY_HASH_MODES:
        raise ValueError(
            f"Unsupported disassembly hash mode '{hash_mode}'. Expected one of: "
            f"{', '.join(sorted(DISASSEMBLY_HASH_MODES))}."
        )
    return normalized


def _file_size_from_path(file_path: str | None) -> int | None:
    if file_path and os.path.exists(file_path):
        return os.path.getsize(file_path)
    return None


def summarize_callgraph(callgraph: Any) -> dict[str, Any] | None:
    if not isinstance(callgraph, dict):
        return None
    external = callgraph.get("external") or []
    return {
        "version": _safe_int(callgraph.get("version")) or 1,
        "node_count": (
            _safe_int(callgraph.get("node_count")) or len(callgraph.get("nodes") or [])
        ),
        "edge_count": (
            _safe_int(callgraph.get("edge_count")) or len(callgraph.get("edges") or [])
        ),
        "external_count": len(external) if isinstance(external, list) else 0,
    }


def summarize_security_properties(metadata: dict[str, Any]) -> dict[str, Any] | None:
    properties = coerce_json_object(metadata.get("security_properties"))
    if "nx" not in properties and metadata.get("has_nx") is not None:
        properties["nx"] = metadata.get("has_nx")
    if "pie" not in properties and metadata.get("is_pie") is not None:
        properties["pie"] = metadata.get("is_pie")
    if "canary" not in properties and metadata.get("has_canary") is not None:
        properties["canary"] = metadata.get("has_canary")
    if "relro" not in properties and metadata.get("relro") is not None:
        properties["relro"] = metadata.get("relro")
    return properties or None


def sanitize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    sanitized = make_json_safe(deepcopy(metadata))
    sanitized.pop("disassembled_functions", None)
    callgraph_summary = summarize_callgraph(sanitized.get("callgraph"))
    if callgraph_summary:
        sanitized["callgraph"] = callgraph_summary
    return sanitized


def extract_symbols(metadata: dict[str, Any]) -> list[dict]:
    symbols = []
    seen = set()
    for source in SYMBOL_SOURCES:
        for entry in metadata.get(source, []) or []:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name", "")).strip()
            if not name:
                continue
            address = entry.get("address") or entry.get("rva_start")
            if address is not None:
                address = str(address)
            default_is_function = source.endswith("functions") or source in {
                "functions",
                "imports",
                "exports",
            }
            row = {
                "name": name,
                "source": source,
                "address": address,
                "size": _safe_int(entry.get("size") or entry.get("length")),
                "is_imported": entry.get("is_imported", source == "imports"),
                "is_exported": entry.get("is_exported", source == "exports"),
                "is_function": entry.get("is_function", default_is_function),
                "is_variable": entry.get("is_variable", False),
                "metadata": optional_json_object(
                    {
                        key: value
                        for key, value in entry.items()
                        if key
                        not in {
                            "name",
                            "address",
                            "rva_start",
                            "size",
                            "length",
                            "is_imported",
                            "is_exported",
                            "is_function",
                            "is_variable",
                        }
                    }
                ),
            }
            dedupe_key = (
                row["source"],
                row["name"],
                row["address"],
                row["size"],
                row["is_imported"],
                row["is_exported"],
                row["is_function"],
                row["is_variable"],
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            symbols.append(row)
    return symbols


def extract_dependencies(metadata: dict[str, Any]) -> list[dict]:
    dependencies = []
    seen = set()

    def add_dependency(
        source: str, name: str, *, version=None, tag=None, purl=None, metadata_obj=None
    ):
        dep_name = str(name).strip() if name else ""
        if not dep_name:
            return
        dep_key = (
            source,
            dep_name,
            version,
            tag,
            purl,
            (
                json.dumps(metadata_obj, sort_keys=True, default=str)
                if metadata_obj
                else None
            ),
        )
        if dep_key in seen:
            return
        seen.add(dep_key)
        dependencies.append(
            {
                "source": source,
                "name": dep_name,
                "version": version,
                "tag": tag,
                "purl": purl,
                "metadata": metadata_obj,
            }
        )

    for entry in metadata.get("dynamic_entries", []) or []:
        if isinstance(entry, dict):
            add_dependency(
                "dynamic_entries",
                entry.get("name"),
                version=entry.get("version"),
                tag=entry.get("tag"),
                purl=entry.get("purl"),
                metadata_obj=optional_json_object(
                    {
                        k: v
                        for k, v in entry.items()
                        if k not in {"name", "version", "tag", "purl"}
                    }
                ),
            )

    for entry in metadata.get("libraries", []) or []:
        if isinstance(entry, dict):
            add_dependency(
                "libraries",
                entry.get("name"),
                version=entry.get("version"),
                tag=entry.get("tag"),
                purl=entry.get("purl"),
                metadata_obj=optional_json_object(
                    {
                        k: v
                        for k, v in entry.items()
                        if k not in {"name", "version", "tag", "purl"}
                    }
                ),
            )

    import_dependencies = metadata.get("import_dependencies") or {}
    if isinstance(import_dependencies, dict):
        for name, entry in (import_dependencies.get("libraries") or {}).items():
            if isinstance(entry, dict):
                add_dependency(
                    "import_dependencies",
                    name,
                    version=entry.get("version"),
                    tag=entry.get("type"),
                    purl=entry.get("purl"),
                    metadata_obj=entry,
                )
        for edge in import_dependencies.get("dependencies") or []:
            if isinstance(edge, dict):
                target = edge.get("target") or edge.get("name") or edge.get("library")
                add_dependency(
                    "import_dependency_edges",
                    target,
                    tag=edge.get("type") or edge.get("tag"),
                    purl=edge.get("purl"),
                    metadata_obj=edge,
                )

    for go_dep_name, go_dep in (metadata.get("go_dependencies") or {}).items():
        if isinstance(go_dep, dict):
            add_dependency(
                "go_dependencies",
                go_dep_name,
                version=go_dep.get("version"),
                tag="golang",
                purl=f"pkg:golang/{go_dep_name.lower()}@{go_dep.get('version')}"
                if go_dep.get("version")
                else f"pkg:golang/{go_dep_name.lower()}",
                metadata_obj=go_dep,
            )

    for rust_dep in metadata.get("rust_dependencies", []) or []:
        if isinstance(rust_dep, dict):
            add_dependency(
                "rust_dependencies",
                rust_dep.get("name"),
                version=rust_dep.get("version"),
                tag=rust_dep.get("kind") or "cargo",
                purl=(
                    f"pkg:cargo/{rust_dep.get('name')}@{rust_dep.get('version')}"
                    if rust_dep.get("name") and rust_dep.get("version")
                    else None
                ),
                metadata_obj=rust_dep,
            )

    dotnet_dependencies = metadata.get("dotnet_dependencies") or {}
    if isinstance(dotnet_dependencies, dict):
        for key, entry in (dotnet_dependencies.get("libraries") or {}).items():
            if not isinstance(entry, dict):
                continue
            name, _, version = key.partition("/")
            add_dependency(
                "dotnet_dependencies",
                name,
                version=version or None,
                tag=entry.get("type") or "nuget",
                purl=f"pkg:nuget/{name}@{version}" if version else f"pkg:nuget/{name}",
                metadata_obj=entry,
            )

    return dependencies


def extract_function_fingerprints(
    metadata: dict[str, Any], *, hash_mode: str = "both"
) -> list[dict]:
    functions = []
    hash_mode = _normalize_hash_mode(hash_mode)
    disassembled_functions = metadata.get("disassembled_functions") or {}
    if not isinstance(disassembled_functions, dict):
        return functions
    include_assembly_hash = hash_mode in {"assembly", "both"}
    include_instruction_hash = hash_mode in {"instruction", "both"}
    for function_key, function_data in disassembled_functions.items():
        if not isinstance(function_data, dict):
            continue
        function_name = function_data.get("name")
        if not function_name:
            continue
        extra_metadata = optional_json_object(
            {
                "instructions_with_registers": function_data.get(
                    "instructions_with_registers"
                ),
            }
        )
        if extra_metadata and not any(
            value is not None for value in extra_metadata.values()
        ):
            extra_metadata = None
        functions.append(
            {
                "function_key": function_key,
                "name": function_name,
                "address": function_data.get("address"),
                "rva_or_address": function_data.get("rvaOrAddress"),
                "assembly_hash": function_data.get("assembly_hash")
                if include_assembly_hash
                else None,
                "instruction_hash": (
                    function_data.get("instruction_hash")
                    if include_instruction_hash
                    else None
                ),
                "instruction_count": function_data.get("instruction_count"),
                "function_type": function_data.get("function_type"),
                "has_indirect_call": function_data.get("has_indirect_call"),
                "has_pac": function_data.get("has_pac"),
                "has_system_call": function_data.get("has_system_call"),
                "has_security_feature": function_data.get("has_security_feature"),
                "has_crypto_call": function_data.get("has_crypto_call"),
                "has_gpu_call": function_data.get("has_gpu_call"),
                "has_loop": function_data.get("has_loop"),
                "instruction_metrics": function_data.get("instruction_metrics"),
                "regs_read": function_data.get("regs_read"),
                "regs_written": function_data.get("regs_written"),
                "used_simd_reg_types": function_data.get("used_simd_reg_types"),
                "direct_calls": function_data.get("direct_calls"),
                "direct_call_targets": function_data.get("direct_call_targets"),
                "proprietary_instructions": function_data.get(
                    "proprietary_instructions"
                ),
                "sreg_interactions": function_data.get("sreg_interactions"),
                **({"metadata": extra_metadata} if extra_metadata else {}),
            }
        )
    return functions


def summarize_binary_metadata(
    metadata: dict[str, Any], *, hash_mode: str = "both"
) -> dict[str, Any]:
    sanitized_metadata = sanitize_metadata(metadata)
    symbols = extract_symbols(metadata)
    dependencies = extract_dependencies(metadata)
    function_fingerprints = extract_function_fingerprints(metadata, hash_mode=hash_mode)
    file_path = metadata.get("file_path") or metadata.get("name")
    build_info = make_json_safe(coerce_json_object(metadata.get("build_info"))) or None
    security_properties = make_json_safe(summarize_security_properties(metadata))
    callgraph_summary = make_json_safe(summarize_callgraph(metadata.get("callgraph")))
    summary = dict(sanitized_metadata)
    summary["metadata_json"] = sanitized_metadata
    summary["build_info"] = build_info
    summary["security_properties"] = security_properties
    summary["callgraph"] = callgraph_summary
    summary["file_size"] = _file_size_from_path(file_path)
    summary["symbol_count"] = len(symbols)
    summary["imported_library_count"] = len(dependencies)
    summary["function_count"] = len(function_fingerprints)
    summary["disassembly_enabled"] = bool(function_fingerprints)
    return {
        "summary": summary,
        "symbols": symbols,
        "dependencies": dependencies,
        "function_fingerprints": function_fingerprints,
    }


def normalize_ingest_records(
    *,
    metadata: dict[str, Any],
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
    hash_mode: str = "both",
) -> dict[str, Any]:
    summary_bundle = summarize_binary_metadata(metadata, hash_mode=hash_mode)
    summary = summary_bundle["summary"]
    binary_path = binary_file_path or metadata.get("file_path") or metadata.get("name")
    if binary_path:
        summary["file_path"] = str(binary_path)
    build_metadata_obj = coerce_json_object(build_metadata) or None
    resolved_target_os = target_os or (
        build_metadata_obj.get("target_os") if build_metadata_obj else None
    )
    resolved_target_arch = target_arch or (
        build_metadata_obj.get("target_arch") if build_metadata_obj else None
    )
    resolved_is_stripped = is_stripped
    if resolved_is_stripped is None:
        resolved_is_stripped = (summary.get("security_properties") or {}).get(
            "stripped"
        )
    return {
        "project": {
            "name": project_name,
            "purl": project_purl,
            "ecosystem": ecosystem,
            "metadata": project_metadata,
            "source_sbom": source_sbom,
        },
        "build": {
            "build_system": build_system,
            "target_os": resolved_target_os,
            "target_arch": resolved_target_arch,
            "target_triplet": target_triplet,
            "llvm_target_tuple": metadata.get("llvm_target_tuple"),
            "build_mode": build_mode,
            "optimization": optimization,
            "is_stripped": resolved_is_stripped,
            "metadata": build_metadata_obj,
        },
        "binary": {
            "binary_file_path": binary_path or project_name,
            "relative_path": relative_binary_path(binary_path, relative_to)
            if binary_path
            else None,
            "metadata": summary,
        },
        "symbols": summary_bundle["symbols"],
        "dependencies": summary_bundle["dependencies"],
        "function_fingerprints": summary_bundle["function_fingerprints"],
    }


def relative_binary_path(
    file_path: str | os.PathLike, relative_to: str | os.PathLike | None = None
) -> str:
    path_obj = Path(file_path)
    if not relative_to:
        return path_obj.name
    try:
        return str(path_obj.resolve().relative_to(Path(relative_to).resolve()))
    except ValueError:
        return path_obj.name
