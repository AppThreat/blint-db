from __future__ import annotations

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import PurePath
from typing import Iterable, Sequence

from blint_db import (
    BLINT_DB_FILE,
    BLINT_DB_SCHEMA_FAMILY,
    BLINT_DB_SCHEMA_VERSION,
    SQLITE_TIMEOUT,
)
from blint_db.utils.json import canonical_json_dumps, coerce_json_object

_SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = MEMORY;

CREATE TABLE IF NOT EXISTS SchemaMeta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Projects (
    project_id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    purl TEXT,
    ecosystem TEXT,
    metadata_json TEXT,
    source_sbom_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Builds (
    build_id INTEGER PRIMARY KEY AUTOINCREMENT,
    build_key TEXT NOT NULL UNIQUE,
    project_id INTEGER NOT NULL,
    build_system TEXT NOT NULL,
    target_os TEXT,
    target_arch TEXT,
    target_triplet TEXT,
    llvm_target_tuple TEXT,
    build_mode TEXT,
    optimization TEXT,
    is_stripped INTEGER,
    metadata_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES Projects(project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS Binaries (
    binary_id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_key TEXT NOT NULL UNIQUE,
    build_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    relative_path TEXT,
    name TEXT NOT NULL,
    binary_type TEXT,
    exe_type TEXT,
    machine_type TEXT,
    llvm_target_tuple TEXT,
    language TEXT,
    compiler_version TEXT,
    linker_version TEXT,
    sha256 TEXT,
    sha1 TEXT,
    md5 TEXT,
    is_shared_library INTEGER,
    is_pie INTEGER,
    has_nx INTEGER,
    has_canary INTEGER,
    security_stripped INTEGER,
    relro TEXT,
    file_size INTEGER,
    imported_library_count INTEGER NOT NULL DEFAULT 0,
    symbol_count INTEGER NOT NULL DEFAULT 0,
    function_count INTEGER NOT NULL DEFAULT 0,
    disassembly_enabled INTEGER NOT NULL DEFAULT 0,
    callgraph_version INTEGER,
    callgraph_node_count INTEGER,
    callgraph_edge_count INTEGER,
    callgraph_external_count INTEGER,
    build_info_json TEXT,
    security_properties_json TEXT,
    callgraph_json TEXT,
    metadata_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (build_id) REFERENCES Builds(build_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS Symbols (
    symbol_id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    address TEXT,
    size INTEGER,
    is_imported INTEGER,
    is_exported INTEGER,
    is_function INTEGER,
    is_variable INTEGER,
    metadata_json TEXT,
    FOREIGN KEY (binary_id) REFERENCES Binaries(binary_id) ON DELETE CASCADE,
    UNIQUE(binary_id, source, name, address, size)
);

CREATE TABLE IF NOT EXISTS Dependencies (
    dependency_id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT,
    tag TEXT,
    purl TEXT,
    metadata_json TEXT,
    FOREIGN KEY (binary_id) REFERENCES Binaries(binary_id) ON DELETE CASCADE,
    UNIQUE(binary_id, source, name, version, tag, purl)
);

CREATE TABLE IF NOT EXISTS FunctionFingerprints (
    function_id INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    function_key TEXT NOT NULL,
    name TEXT NOT NULL,
    address TEXT,
    rva_or_address TEXT,
    assembly_hash TEXT,
    instruction_hash TEXT,
    instruction_count INTEGER,
    function_type TEXT,
    has_indirect_call INTEGER,
    has_pac INTEGER,
    has_system_call INTEGER,
    has_security_feature INTEGER,
    has_crypto_call INTEGER,
    has_gpu_call INTEGER,
    has_loop INTEGER,
    instruction_metrics_json TEXT,
    regs_read_json TEXT,
    regs_written_json TEXT,
    used_simd_reg_types_json TEXT,
    direct_calls_json TEXT,
    direct_call_targets_json TEXT,
    proprietary_instructions_json TEXT,
    sreg_interactions_json TEXT,
    metadata_json TEXT,
    FOREIGN KEY (binary_id) REFERENCES Binaries(binary_id) ON DELETE CASCADE,
    UNIQUE(binary_id, function_key)
);

CREATE INDEX IF NOT EXISTS idx_projects_name ON Projects(name);
CREATE INDEX IF NOT EXISTS idx_projects_purl ON Projects(purl);
CREATE INDEX IF NOT EXISTS idx_builds_project ON Builds(project_id);
CREATE INDEX IF NOT EXISTS idx_binaries_build ON Binaries(build_id);
CREATE INDEX IF NOT EXISTS idx_binaries_sha256 ON Binaries(sha256);
CREATE INDEX IF NOT EXISTS idx_binaries_language ON Binaries(language);
CREATE INDEX IF NOT EXISTS idx_symbols_name ON Symbols(name);
CREATE INDEX IF NOT EXISTS idx_symbols_source ON Symbols(source);
CREATE INDEX IF NOT EXISTS idx_functions_instruction_hash ON FunctionFingerprints(instruction_hash);
CREATE INDEX IF NOT EXISTS idx_functions_assembly_hash ON FunctionFingerprints(assembly_hash);
"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json_dump(value):
    if value is None:
        return None
    return canonical_json_dumps(value)


def _bool_to_int(value):
    if value is None:
        return None
    return int(bool(value))


def _identity_key(payload: dict) -> str:
    return canonical_json_dumps(payload)


def _display_name(binary_file_path: str, metadata: dict | None = None) -> str:
    metadata = metadata or {}
    raw_name = str(metadata.get("name") or binary_file_path)
    return os.path.basename(raw_name.replace("\\", "/")) or os.path.basename(
        binary_file_path
    )


@contextmanager
def get_connection(db_file: str | None = None):
    database_file = db_file or BLINT_DB_FILE
    connection = sqlite3.connect(database_file, timeout=SQLITE_TIMEOUT)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def execute_statement(
    statement: str,
    arguments: Sequence | None = None,
    *,
    db_file: str | None = None,
):
    with get_connection(db_file) as connection:
        cursor = connection.execute(statement, arguments or [])
        return cursor.fetchall()


def clear_sqlite_database(db_file: str | None = None):
    database_file = db_file or BLINT_DB_FILE
    if os.path.isfile(database_file):
        os.remove(database_file)


def get_schema_meta(db_file: str | None = None) -> dict[str, str]:
    database_file = db_file or BLINT_DB_FILE
    if not os.path.exists(database_file):
        return {}
    try:
        with get_connection(database_file) as connection:
            rows = connection.execute("SELECT key, value FROM SchemaMeta").fetchall()
    except sqlite3.Error:
        return {}
    return {str(row["key"]): str(row["value"]) for row in rows}


def get_schema_version(db_file: str | None = None) -> int | None:
    meta = get_schema_meta(db_file)
    version = meta.get("schema_version")
    return int(version) if version is not None else None


def _validate_schema_contract(db_file: str | None = None) -> None:
    database_file = db_file or BLINT_DB_FILE
    if not os.path.exists(database_file):
        return
    meta = get_schema_meta(database_file)
    if not meta:
        raise RuntimeError(
            f"Existing database '{database_file}' is not a recognized {BLINT_DB_SCHEMA_FAMILY} "
            f"schema. Remove it or use --clean-start to recreate a v{BLINT_DB_SCHEMA_VERSION} database."
        )
    if meta.get("schema_family") != BLINT_DB_SCHEMA_FAMILY:
        raise RuntimeError(
            f"Database '{database_file}' belongs to schema family "
            f"'{meta.get('schema_family')}', expected '{BLINT_DB_SCHEMA_FAMILY}'."
        )
    if int(meta.get("schema_version", "0")) != BLINT_DB_SCHEMA_VERSION:
        raise RuntimeError(
            f"Database '{database_file}' has schema version {meta.get('schema_version')}, "
            f"expected {BLINT_DB_SCHEMA_VERSION}. Recreate it with --clean-start."
        )


def create_database(db_file: str | None = None):
    database_file = db_file or BLINT_DB_FILE
    if os.path.exists(database_file):
        _validate_schema_contract(database_file)
    with get_connection(database_file) as connection:
        connection.executescript(_SCHEMA_SQL)
        now = _utc_now()
        meta_rows = (
            ("schema_family", BLINT_DB_SCHEMA_FAMILY),
            ("schema_version", str(BLINT_DB_SCHEMA_VERSION)),
            ("created_at", now),
            ("updated_at", now),
        )
        connection.executemany(
            "INSERT INTO SchemaMeta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            meta_rows,
        )


def ensure_database(db_file: str | None = None):
    database_file = db_file or BLINT_DB_FILE
    if not os.path.exists(database_file):
        create_database(database_file)
        return
    _validate_schema_contract(database_file)


def upsert_project(
    connection: sqlite3.Connection,
    project_name: str,
    *,
    purl: str | None = None,
    ecosystem: str | None = None,
    metadata=None,
    source_sbom=None,
) -> int:
    now = _utc_now()
    project_key = _identity_key(
        {
            "name": project_name,
            "purl": purl,
            "ecosystem": ecosystem,
        }
    )
    connection.execute(
        """
        INSERT INTO Projects(
            project_key, name, purl, ecosystem, metadata_json, source_sbom_json, created_at, updated_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(project_key) DO UPDATE SET
            name=excluded.name,
            purl=excluded.purl,
            ecosystem=excluded.ecosystem,
            metadata_json=COALESCE(excluded.metadata_json, Projects.metadata_json),
            source_sbom_json=COALESCE(excluded.source_sbom_json, Projects.source_sbom_json),
            updated_at=excluded.updated_at
        """,
        (
            project_key,
            project_name,
            purl,
            ecosystem,
            _json_dump(metadata),
            _json_dump(source_sbom),
            now,
            now,
        ),
    )
    row = connection.execute(
        "SELECT project_id FROM Projects WHERE project_key=?",
        (project_key,),
    ).fetchone()
    return int(row["project_id"])


def upsert_build(
    connection: sqlite3.Connection,
    project_id: int,
    *,
    build_system: str,
    target_os: str | None = None,
    target_arch: str | None = None,
    target_triplet: str | None = None,
    llvm_target_tuple: str | None = None,
    build_mode: str | None = None,
    optimization: str | None = None,
    is_stripped=None,
    metadata=None,
) -> int:
    now = _utc_now()
    metadata_obj = coerce_json_object(metadata) or None
    build_key = _identity_key(
        {
            "project_id": project_id,
            "build_system": build_system,
            "target_os": target_os,
            "target_arch": target_arch,
            "target_triplet": target_triplet,
            "llvm_target_tuple": llvm_target_tuple,
            "build_mode": build_mode,
            "optimization": optimization,
            "is_stripped": is_stripped,
            "metadata": metadata_obj,
        }
    )
    connection.execute(
        """
        INSERT INTO Builds(
            build_key, project_id, build_system, target_os, target_arch, target_triplet,
            llvm_target_tuple, build_mode, optimization, is_stripped, metadata_json,
            created_at, updated_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(build_key) DO UPDATE SET
            metadata_json=COALESCE(excluded.metadata_json, Builds.metadata_json),
            updated_at=excluded.updated_at
        """,
        (
            build_key,
            project_id,
            build_system,
            target_os,
            target_arch,
            target_triplet,
            llvm_target_tuple,
            build_mode,
            optimization,
            _bool_to_int(is_stripped),
            _json_dump(metadata_obj),
            now,
            now,
        ),
    )
    row = connection.execute(
        "SELECT build_id FROM Builds WHERE build_key=?",
        (build_key,),
    ).fetchone()
    return int(row["build_id"])


def upsert_binary(
    connection: sqlite3.Connection,
    build_id: int,
    binary_file_path: str | PurePath,
    *,
    relative_path: str | None = None,
    metadata: dict | None = None,
) -> int:
    metadata = metadata or {}
    if isinstance(binary_file_path, PurePath):
        binary_file_path = str(binary_file_path)
    display_name = _display_name(binary_file_path, metadata)
    hashes = coerce_json_object(metadata.get("hashes"))
    build_info = coerce_json_object(metadata.get("build_info")) or None
    security_properties = (
        coerce_json_object(metadata.get("security_properties")) or None
    )
    callgraph = coerce_json_object(metadata.get("callgraph")) or None
    binary_key = _identity_key(
        {
            "build_id": build_id,
            "relative_path": relative_path,
            "file_path": binary_file_path,
            "sha256": hashes.get("sha256"),
            "name": display_name,
        }
    )
    now = _utc_now()
    connection.execute(
        """
        INSERT INTO Binaries(
            binary_key, build_id, file_path, relative_path, name, binary_type, exe_type,
            machine_type, llvm_target_tuple, language, compiler_version, linker_version,
            sha256, sha1, md5, is_shared_library, is_pie, has_nx, has_canary,
            security_stripped, relro, file_size, imported_library_count, symbol_count,
            function_count, disassembly_enabled, callgraph_version, callgraph_node_count,
            callgraph_edge_count, callgraph_external_count, build_info_json,
            security_properties_json, callgraph_json, metadata_json, created_at, updated_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(binary_key) DO UPDATE SET
            file_path=excluded.file_path,
            relative_path=excluded.relative_path,
            name=excluded.name,
            binary_type=excluded.binary_type,
            exe_type=excluded.exe_type,
            machine_type=excluded.machine_type,
            llvm_target_tuple=excluded.llvm_target_tuple,
            language=excluded.language,
            compiler_version=excluded.compiler_version,
            linker_version=excluded.linker_version,
            sha256=excluded.sha256,
            sha1=excluded.sha1,
            md5=excluded.md5,
            is_shared_library=excluded.is_shared_library,
            is_pie=excluded.is_pie,
            has_nx=excluded.has_nx,
            has_canary=excluded.has_canary,
            security_stripped=excluded.security_stripped,
            relro=excluded.relro,
            file_size=excluded.file_size,
            imported_library_count=excluded.imported_library_count,
            symbol_count=excluded.symbol_count,
            function_count=excluded.function_count,
            disassembly_enabled=excluded.disassembly_enabled,
            callgraph_version=excluded.callgraph_version,
            callgraph_node_count=excluded.callgraph_node_count,
            callgraph_edge_count=excluded.callgraph_edge_count,
            callgraph_external_count=excluded.callgraph_external_count,
            build_info_json=excluded.build_info_json,
            security_properties_json=excluded.security_properties_json,
            callgraph_json=excluded.callgraph_json,
            metadata_json=excluded.metadata_json,
            updated_at=excluded.updated_at
        """,
        (
            binary_key,
            build_id,
            binary_file_path,
            relative_path,
            display_name,
            metadata.get("binary_type"),
            metadata.get("exe_type"),
            metadata.get("machine_type"),
            metadata.get("llvm_target_tuple"),
            build_info.get("language") if build_info else None,
            build_info.get("compiler_version") if build_info else None,
            build_info.get("linker_version") if build_info else None,
            hashes.get("sha256"),
            hashes.get("sha1"),
            hashes.get("md5"),
            _bool_to_int(metadata.get("is_shared_library")),
            _bool_to_int(
                security_properties.get("pie") if security_properties else None
            ),
            _bool_to_int(
                security_properties.get("nx") if security_properties else None
            ),
            _bool_to_int(
                security_properties.get("canary") if security_properties else None
            ),
            _bool_to_int(
                security_properties.get("stripped") if security_properties else None
            ),
            security_properties.get("relro") if security_properties else None,
            metadata.get("file_size"),
            int(metadata.get("imported_library_count", 0)),
            int(metadata.get("symbol_count", 0)),
            int(metadata.get("function_count", 0)),
            _bool_to_int(metadata.get("disassembly_enabled")),
            callgraph.get("version") if callgraph else None,
            callgraph.get("node_count") if callgraph else None,
            callgraph.get("edge_count") if callgraph else None,
            callgraph.get("external_count") if callgraph else None,
            _json_dump(build_info),
            _json_dump(security_properties),
            _json_dump(callgraph),
            _json_dump(
                metadata.get("metadata_json")
                if "metadata_json" in metadata
                else metadata
            ),
            now,
            now,
        ),
    )
    row = connection.execute(
        "SELECT binary_id FROM Binaries WHERE binary_key=?",
        (binary_key,),
    ).fetchone()
    return int(row["binary_id"])


def add_build(connection: sqlite3.Connection, project_id: int, **kwargs) -> int:
    return upsert_build(connection, project_id, **kwargs)


def add_binary(
    connection: sqlite3.Connection,
    build_id: int,
    binary_file_path: str | PurePath,
    **kwargs,
) -> int:
    return upsert_binary(connection, build_id, binary_file_path, **kwargs)


def replace_binary_symbols(
    connection: sqlite3.Connection,
    binary_id: int,
    symbols: Iterable[dict],
):
    connection.execute("DELETE FROM Symbols WHERE binary_id=?", (binary_id,))
    connection.executemany(
        """
        INSERT OR IGNORE INTO Symbols(
            binary_id, name, source, address, size, is_imported, is_exported,
            is_function, is_variable, metadata_json
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                binary_id,
                symbol["name"],
                symbol["source"],
                symbol.get("address"),
                symbol.get("size"),
                _bool_to_int(symbol.get("is_imported")),
                _bool_to_int(symbol.get("is_exported")),
                _bool_to_int(symbol.get("is_function")),
                _bool_to_int(symbol.get("is_variable")),
                _json_dump(symbol.get("metadata")),
            )
            for symbol in symbols
            if symbol.get("name") and symbol.get("source")
        ],
    )


def replace_binary_dependencies(
    connection: sqlite3.Connection,
    binary_id: int,
    dependencies: Iterable[dict],
):
    connection.execute("DELETE FROM Dependencies WHERE binary_id=?", (binary_id,))
    connection.executemany(
        """
        INSERT OR IGNORE INTO Dependencies(
            binary_id, source, name, version, tag, purl, metadata_json
        ) VALUES(?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                binary_id,
                dependency["source"],
                dependency["name"],
                dependency.get("version"),
                dependency.get("tag"),
                dependency.get("purl"),
                _json_dump(dependency.get("metadata")),
            )
            for dependency in dependencies
            if dependency.get("name") and dependency.get("source")
        ],
    )


def replace_binary_function_fingerprints(
    connection: sqlite3.Connection,
    binary_id: int,
    functions: Iterable[dict],
):
    connection.execute(
        "DELETE FROM FunctionFingerprints WHERE binary_id=?", (binary_id,)
    )
    connection.executemany(
        """
        INSERT OR IGNORE INTO FunctionFingerprints(
            binary_id, function_key, name, address, rva_or_address, assembly_hash,
            instruction_hash, instruction_count, function_type, has_indirect_call,
            has_pac, has_system_call, has_security_feature, has_crypto_call,
            has_gpu_call, has_loop, instruction_metrics_json, regs_read_json,
            regs_written_json, used_simd_reg_types_json, direct_calls_json,
            direct_call_targets_json, proprietary_instructions_json,
            sreg_interactions_json, metadata_json
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                binary_id,
                function["function_key"],
                function["name"],
                function.get("address"),
                function.get("rva_or_address"),
                function.get("assembly_hash"),
                function.get("instruction_hash"),
                function.get("instruction_count"),
                function.get("function_type"),
                _bool_to_int(function.get("has_indirect_call")),
                _bool_to_int(function.get("has_pac")),
                _bool_to_int(function.get("has_system_call")),
                _bool_to_int(function.get("has_security_feature")),
                _bool_to_int(function.get("has_crypto_call")),
                _bool_to_int(function.get("has_gpu_call")),
                _bool_to_int(function.get("has_loop")),
                _json_dump(function.get("instruction_metrics")),
                _json_dump(function.get("regs_read")),
                _json_dump(function.get("regs_written")),
                _json_dump(function.get("used_simd_reg_types")),
                _json_dump(function.get("direct_calls")),
                _json_dump(function.get("direct_call_targets")),
                _json_dump(function.get("proprietary_instructions")),
                _json_dump(function.get("sreg_interactions")),
                _json_dump(function.get("metadata")),
            )
            for function in functions
            if function.get("function_key") and function.get("name")
        ],
    )


def update_binary_statistics(
    connection: sqlite3.Connection,
    binary_id: int,
):
    symbol_count = connection.execute(
        "SELECT COUNT(*) AS count FROM Symbols WHERE binary_id=?",
        (binary_id,),
    ).fetchone()["count"]
    function_count = connection.execute(
        "SELECT COUNT(*) AS count FROM FunctionFingerprints WHERE binary_id=?",
        (binary_id,),
    ).fetchone()["count"]
    dependency_count = connection.execute(
        "SELECT COUNT(*) AS count FROM Dependencies WHERE binary_id=?",
        (binary_id,),
    ).fetchone()["count"]
    connection.execute(
        """
        UPDATE Binaries
        SET symbol_count=?, function_count=?, imported_library_count=?, disassembly_enabled=?, updated_at=?
        WHERE binary_id=?
        """,
        (
            int(symbol_count),
            int(function_count),
            int(dependency_count),
            int(function_count > 0),
            _utc_now(),
            binary_id,
        ),
    )


def fetch_binary(binary_id: int, *, db_file: str | None = None) -> dict | None:
    rows = execute_statement(
        """
        SELECT
            Binaries.binary_id,
            Binaries.name AS binary_name,
            Binaries.binary_type,
            Binaries.machine_type,
            Binaries.llvm_target_tuple,
            Binaries.sha256,
            Projects.name AS project_name,
            Projects.purl AS project_purl,
            Builds.build_system,
            Builds.target_os,
            Builds.target_arch
        FROM Binaries
        JOIN Builds ON Binaries.build_id = Builds.build_id
        JOIN Projects ON Builds.project_id = Projects.project_id
        WHERE Binaries.binary_id = ?
        """,
        (binary_id,),
        db_file=db_file,
    )
    return dict(rows[0]) if rows else None


def _clean_nonempty_values(values: Sequence[str] | None) -> list[str]:
    if not values:
        return []
    return sorted({value for value in values if value})


def _symbol_sources_clause(sources: Sequence[str] | None) -> tuple[str, list[str]]:
    cleaned_sources = _clean_nonempty_values(sources)
    if not cleaned_sources:
        return "", []
    return (
        " AND Symbols.source IN ({})".format(",".join("?" for _ in cleaned_sources)),
        cleaned_sources,
    )


def _function_hash_predicates(
    *,
    instruction_hashes: Sequence[str] | None = None,
    assembly_hashes: Sequence[str] | None = None,
) -> tuple[list[str], list[str]]:
    predicates = []
    params: list[str] = []
    cleaned_instruction_hashes = _clean_nonempty_values(instruction_hashes)
    if cleaned_instruction_hashes:
        predicates.append(
            "FunctionFingerprints.instruction_hash IN ({})".format(
                ",".join("?" for _ in cleaned_instruction_hashes)
            )
        )
        params.extend(cleaned_instruction_hashes)
    cleaned_assembly_hashes = _clean_nonempty_values(assembly_hashes)
    if cleaned_assembly_hashes:
        predicates.append(
            "FunctionFingerprints.assembly_hash IN ({})".format(
                ",".join("?" for _ in cleaned_assembly_hashes)
            )
        )
        params.extend(cleaned_assembly_hashes)
    return predicates, params


def lookup_symbol_matches(
    symbol_names: Sequence[str],
    *,
    db_file: str | None = None,
    sources: Sequence[str] | None = None,
    limit: int = 20,
) -> list[dict]:
    cleaned = _clean_nonempty_values(symbol_names)
    if not cleaned:
        return []
    params: list = list(cleaned)
    query = """
        SELECT
            Binaries.binary_id,
            Binaries.name AS binary_name,
            Projects.name AS project_name,
            Projects.purl AS project_purl,
            COUNT(DISTINCT Symbols.name) AS matched_symbol_count,
            COUNT(*) AS matched_row_count
        FROM Symbols
        JOIN Binaries ON Symbols.binary_id = Binaries.binary_id
        JOIN Builds ON Binaries.build_id = Builds.build_id
        JOIN Projects ON Builds.project_id = Projects.project_id
        WHERE Symbols.name IN ({})
    """.format(",".join("?" for _ in cleaned))
    sources_clause, source_params = _symbol_sources_clause(sources)
    if sources_clause:
        query += sources_clause
        params.extend(source_params)
    query += (
        " GROUP BY Binaries.binary_id"
        " ORDER BY matched_symbol_count DESC, matched_row_count DESC, Binaries.binary_id ASC"
        " LIMIT ?"
    )
    params.append(limit)
    with get_connection(db_file) as connection:
        return [dict(row) for row in connection.execute(query, params).fetchall()]


def lookup_project_symbol_matches(
    symbol_names: Sequence[str],
    *,
    db_file: str | None = None,
    sources: Sequence[str] | None = None,
    limit: int = 20,
) -> list[dict]:
    cleaned = _clean_nonempty_values(symbol_names)
    if not cleaned:
        return []
    params: list = list(cleaned)
    query = """
        SELECT
            Projects.project_id,
            Projects.name AS project_name,
            Projects.purl AS project_purl,
            COUNT(DISTINCT Binaries.binary_id) AS matched_binary_count,
            COUNT(DISTINCT Symbols.name) AS matched_symbol_count,
            COUNT(*) AS matched_row_count
        FROM Symbols
        JOIN Binaries ON Symbols.binary_id = Binaries.binary_id
        JOIN Builds ON Binaries.build_id = Builds.build_id
        JOIN Projects ON Builds.project_id = Projects.project_id
        WHERE Symbols.name IN ({})
    """.format(",".join("?" for _ in cleaned))
    sources_clause, source_params = _symbol_sources_clause(sources)
    if sources_clause:
        query += sources_clause
        params.extend(source_params)
    query += (
        " GROUP BY Projects.project_id"
        " ORDER BY matched_symbol_count DESC, matched_binary_count DESC, "
        "matched_row_count DESC, Projects.project_id ASC"
        " LIMIT ?"
    )
    params.append(limit)
    with get_connection(db_file) as connection:
        return [dict(row) for row in connection.execute(query, params).fetchall()]


def lookup_function_hash_matches(
    *,
    instruction_hashes: Sequence[str] | None = None,
    assembly_hashes: Sequence[str] | None = None,
    db_file: str | None = None,
    limit: int = 20,
) -> list[dict]:
    predicates, params = _function_hash_predicates(
        instruction_hashes=instruction_hashes,
        assembly_hashes=assembly_hashes,
    )
    if not predicates:
        return []
    query = f"""
        SELECT
            Binaries.binary_id,
            Binaries.name AS binary_name,
            Projects.name AS project_name,
            Projects.purl AS project_purl,
            COUNT(DISTINCT FunctionFingerprints.function_key) AS matched_function_count
        FROM FunctionFingerprints
        JOIN Binaries ON FunctionFingerprints.binary_id = Binaries.binary_id
        JOIN Builds ON Binaries.build_id = Builds.build_id
        JOIN Projects ON Builds.project_id = Projects.project_id
        WHERE {" OR ".join(predicates)}
        GROUP BY Binaries.binary_id
        ORDER BY matched_function_count DESC, Binaries.binary_id ASC
        LIMIT ?
    """
    params.append(limit)
    with get_connection(db_file) as connection:
        return [dict(row) for row in connection.execute(query, params).fetchall()]


def lookup_project_function_hash_matches(
    *,
    instruction_hashes: Sequence[str] | None = None,
    assembly_hashes: Sequence[str] | None = None,
    db_file: str | None = None,
    limit: int = 20,
) -> list[dict]:
    predicates, params = _function_hash_predicates(
        instruction_hashes=instruction_hashes,
        assembly_hashes=assembly_hashes,
    )
    if not predicates:
        return []
    query = f"""
        SELECT
            Projects.project_id,
            Projects.name AS project_name,
            Projects.purl AS project_purl,
            COUNT(DISTINCT Binaries.binary_id) AS matched_binary_count,
            COUNT(DISTINCT FunctionFingerprints.function_key) AS matched_function_count,
            COUNT(*) AS matched_row_count
        FROM FunctionFingerprints
        JOIN Binaries ON FunctionFingerprints.binary_id = Binaries.binary_id
        JOIN Builds ON Binaries.build_id = Builds.build_id
        JOIN Projects ON Builds.project_id = Projects.project_id
        WHERE {" OR ".join(predicates)}
        GROUP BY Projects.project_id
        ORDER BY matched_function_count DESC, matched_binary_count DESC,
            matched_row_count DESC, Projects.project_id ASC
        LIMIT ?
    """
    params.append(limit)
    with get_connection(db_file) as connection:
        return [dict(row) for row in connection.execute(query, params).fetchall()]
