"""Query-contract tests between blint-db and blint.

These tests run blint's *real* lookup code (``blint.db`` at the version pinned
in pyproject.toml) against the committed sample database
``tests/data/blintdb-sample.db``. They are the contract between the two
repositories: if blint changes a query shape or a capability probe that the
committed schema cannot serve, something here must fail — a test written
against guessed SQL cannot do that, so nothing in this file re-implements a
blint query.

The sample is symbol-only by design, which also pins the degradation side of
the contract: the similarity-hash columns exist in the schema but hold no
values, and blint must report that state by name rather than as an empty
lookup.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from blint.db import (
    blintdb_fuzzy_layer_state,
    blintdb_hash_capabilities,
    blintdb_member_layer_state,
    detect_binaries_utilized,
    get_schema_meta,
    is_supported_blintdb,
    lookup_project_matches,
)

SAMPLE_DB = Path(__file__).resolve().parent / "data" / "blintdb-sample.db"

# The sample corpus: three wrapdb projects with distinct symbol spaces,
# built symbol-only from shared libraries. Kept in sync with
# scripts/build_sample_db.sh, which regenerates the committed database.
SAMPLE_PROJECTS = ("zlib", "bzip2", "c-ares")


@pytest.fixture(scope="module")
def sample_db() -> Path:
    assert SAMPLE_DB.exists(), (
        f"Committed sample database is missing: {SAMPLE_DB}. "
        "Rebuild it with scripts/build_sample_db.sh and commit the result."
    )
    return SAMPLE_DB


@pytest.fixture(scope="module")
def connection(sample_db: Path):
    conn = sqlite3.connect(sample_db)
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


def _project_purl(connection: sqlite3.Connection, project_name: str) -> str:
    row = connection.execute(
        "SELECT purl FROM Projects WHERE name = ? ORDER BY project_id LIMIT 1",
        (project_name,),
    ).fetchone()
    assert row and row["purl"], f"sample has no purl for project {project_name}"
    return str(row["purl"])


def _project_symbol_source_map(
    connection: sqlite3.Connection, project_name: str
) -> dict[str, list[str]]:
    """One source bucket per blint SYMBOL_SOURCES key, from the sample's rows."""
    rows = connection.execute(
        """
        SELECT Symbols.source AS source, Symbols.name AS name
        FROM Symbols
        JOIN Binaries ON Symbols.binary_id = Binaries.binary_id
        JOIN Builds ON Binaries.build_id = Builds.build_id
        JOIN Projects ON Builds.project_id = Projects.project_id
        WHERE Projects.name = ?
        """,
        (project_name,),
    ).fetchall()
    source_map: dict[str, list[str]] = {}
    for row in rows:
        source_map.setdefault(str(row["source"]), []).append(str(row["name"]))
    assert source_map, f"sample has no symbols for project {project_name}"
    return source_map


def test_committed_sample_is_a_supported_v3_database(sample_db: Path):
    meta = get_schema_meta(str(sample_db))
    assert meta.get("schema_family") == "blint-db"
    assert meta.get("schema_version") == "3"
    assert is_supported_blintdb(str(sample_db)) is True


def test_symbol_only_sample_names_its_unavailable_layers(sample_db: Path):
    """The hash/member layers must report why they cannot run, by name.

    The sample's schema carries the fuzzy/cfg/import-hash and archive_name
    columns. The disassembly-derived columns (fuzzy, cfg) and the member
    column (archive_name) hold no values in a symbol-only build, so those
    layers are unavailable rather than empty — the states are blint constants
    and are asserted by name so a silent rename or a dropped probe fails
    here. ``import_hash`` is the deliberate exception: blint computes it
    during parse, not disassembly, so even the symbol-only sample populates
    it — pinning that branch too, because a producer that stopped recording
    it would silently lose import corroboration in every future database.
    """
    capabilities = blintdb_hash_capabilities(str(sample_db))
    assert capabilities, "capability probe returned nothing for the sample"
    for column in ("fuzzy_hash", "cfg_hash", "import_hash", "archive_name"):
        assert capabilities.get(column) is True, (
            f"sample schema lost the {column} column"
        )
    for column in ("fuzzy_hash", "cfg_hash", "archive_name"):
        assert capabilities.get(f"{column}_populated") is False, (
            f"symbol-only sample must not populate {column}"
        )
    assert capabilities.get("import_hash_populated") is True, (
        "import_hash is parse-time evidence and must be populated even "
        "without disassembly"
    )
    assert (
        blintdb_fuzzy_layer_state(str(sample_db), metadata={})
        == "unavailable_hash_columns_unpopulated"
    )
    assert (
        blintdb_member_layer_state(str(sample_db), metadata={})
        == "unavailable_no_member_rows"
    )


@pytest.mark.parametrize("project_name", SAMPLE_PROJECTS)
def test_blint_symbol_queries_resolve_each_sample_project(
    sample_db: Path, connection: sqlite3.Connection, project_name: str
):
    """blint's real symbol lookup resolves each project from its own symbols."""
    expected_purl = _project_purl(connection, project_name)
    source_map = _project_symbol_source_map(connection, project_name)
    matches = lookup_project_matches(
        source_map,
        binary_metadata={
            "binary_type": "MachO",
            "llvm_target_tuple": "aarch64-apple-macosx",
            "name": project_name,
        },
        db_file=str(sample_db),
    )
    assert matches, f"blint lookup returned no matches for {project_name}"
    assert matches[0]["project_purl"] == expected_purl, (
        f"top match for {project_name} was {matches[0]['project_purl']}"
    )
    assert matches[0]["matched_symbol_count"] > 0
    # Every other returned match must be strictly weaker than the project's
    # own match, so the resolution is ordered, not incidental.
    for other in matches[1:]:
        assert (
            other["matched_symbol_count"] < matches[0]["matched_symbol_count"]
        ), f"{other['project_purl']} matched as strongly as {expected_purl}"


def test_blint_binary_filter_mismatch_falls_back_to_unfiltered_query(
    sample_db: Path, connection: sqlite3.Connection
):
    """A target tuple the sample does not carry still resolves via the retry.

    blint runs the symbol query with binary filters first and retries
    unfiltered when that finds nothing; the contract is that a filtered miss
    on tuple grounds never turns into "no matches". If blint drops the
    retry, this test fails and the change is deliberate.
    """
    expected_purl = _project_purl(connection, "zlib")
    source_map = _project_symbol_source_map(connection, "zlib")
    matches = lookup_project_matches(
        source_map,
        binary_metadata={
            "binary_type": "ELF",
            "llvm_target_tuple": "x86_64-pc-linux-gnu",
            "name": "libz.so.1",
        },
        db_file=str(sample_db),
    )
    assert matches, "unfiltered retry after a tuple miss returned no matches"
    assert matches[0]["project_purl"] == expected_purl


def test_blint_detect_binaries_utilized_reports_zlib_evidence(
    sample_db: Path, connection: sqlite3.Connection
):
    """The SBOM entry point resolves zlib and carries per-match evidence."""
    expected_purl = _project_purl(connection, "zlib")
    source_map = _project_symbol_source_map(connection, "zlib")
    symbols_list = [
        {"name": name, "is_function": True}
        for names in source_map.values()
        for name in names
    ]
    detected, evidence = detect_binaries_utilized(
        symbols_list,
        binary_metadata={
            "binary_type": "MachO",
            "llvm_target_tuple": "aarch64-apple-macosx",
            "name": "libz.1.dylib",
        },
        db_file=str(sample_db),
    )
    assert expected_purl in detected
    zlib_evidence = evidence[expected_purl]
    assert zlib_evidence["project_name"] == "zlib"
    assert zlib_evidence["score"] > 0
    assert zlib_evidence["matched_symbol_count"] > 0
    assert zlib_evidence["matched_symbols"], "no matched symbol evidence"
