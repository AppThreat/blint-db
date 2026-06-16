"""Tests for callgraph corpus storage and binary-vs-source matching."""

from blint_db.handlers.sqlite_handler import (
    create_database,
    execute_statement,
    match_binary_against_source_corpus,
)
from blint_db.ingest import ingest_metadata, ingest_source_callgraph

# A tiny source callgraph in the rusi schema shape.
_SOURCE = {
    "tool": {"name": "rusi"},
    "schema_version": "0.1",
    "call_graph": {
        "nodes": [
            {"id": f"cg-{n}", "qualified_name": n, "local": True}
            for n in ("app::main", "app::helper", "app::leaf")
        ],
        "edges": [
            {"source_id": "cg-app::main", "target_id": "cg-app::helper"},
            {"source_id": "cg-app::helper", "target_id": "cg-app::leaf"},
        ],
    },
}

# A binary whose function names canonicalize onto the source graph.
_BINARY = {
    "file_path": "/tmp/app",
    "name": "/tmp/app",
    "llvm_target_tuple": "x86_64-unknown-linux-gnu",
    "callgraph": {
        "version": 2,
        "nodes": [
            {"id": 0, "key": "0x10::app::main", "name": "app::main", "address": "0x10"},
            {
                "id": 1,
                "key": "0x20::app::helper",
                "name": "app::helper",
                "address": "0x20",
            },
            {"id": 2, "key": "0x30::app::leaf", "name": "app::leaf", "address": "0x30"},
        ],
        "edges": [
            {"src": 0, "dst": 1, "kind": "direct", "confidence": "high"},
            {"src": 1, "dst": 2, "kind": "direct", "confidence": "high"},
        ],
    },
    "disassembled_functions": {
        "0x10::app::main": {"name": "app::main", "instruction_count": 12},
        "0x20::app::helper": {"name": "app::helper", "instruction_count": 8},
        "0x30::app::leaf": {"name": "app::leaf", "instruction_count": 4},
    },
}


def test_schema_includes_callgraph_corpus_tables(tmp_path):
    db_file = tmp_path / "blint-v2.db"
    create_database(str(db_file))
    tables = {
        row["name"]
        for row in execute_statement(
            "SELECT name FROM sqlite_master WHERE type='table'",
            db_file=str(db_file),
        )
    }
    assert {"SourceGraphs", "CallGraphNodes", "CallGraphEdges"}.issubset(tables)


def test_ingest_persists_binary_callgraph_nodes_and_edges(tmp_path):
    db_file = tmp_path / "blint-v2.db"
    result = ingest_metadata(
        metadata=_BINARY,
        db_file=str(db_file),
        project_name="app",
        build_system="manual",
    )
    nodes = execute_statement(
        "SELECT canon_name FROM CallGraphNodes WHERE graph_kind='binary' AND owner_id=?",
        (result["binary_id"],),
        db_file=str(db_file),
    )
    edges = execute_statement(
        "SELECT src_ref, dst_ref, edge_type FROM CallGraphEdges "
        "WHERE graph_kind='binary' AND owner_id=?",
        (result["binary_id"],),
        db_file=str(db_file),
    )
    assert {row["canon_name"] for row in nodes} == {
        "app::main",
        "app::helper",
        "app::leaf",
    }
    assert len(edges) == 2
    assert edges[0]["edge_type"] == "direct"


def test_source_ingest_and_binary_corpus_match(tmp_path):
    db_file = tmp_path / "blint-v2.db"
    ingest_source_callgraph(
        source_callgraph=_SOURCE,
        source_key="app@1.0.0",
        db_file=str(db_file),
        name="app",
        purl="pkg:cargo/app@1.0.0",
    )
    binary = ingest_metadata(
        metadata=_BINARY,
        db_file=str(db_file),
        project_name="app",
        build_system="manual",
    )

    matches = match_binary_against_source_corpus(
        binary["binary_id"], db_file=str(db_file)
    )
    assert matches
    assert matches[0]["source_purl"] == "pkg:cargo/app@1.0.0"
    assert matches[0]["shared_functions"] == 3
    assert matches[0]["source_tool"] == "rusi"


def test_source_ingest_is_idempotent_on_source_key(tmp_path):
    db_file = tmp_path / "blint-v2.db"
    first = ingest_source_callgraph(
        source_callgraph=_SOURCE, source_key="app@1.0.0", db_file=str(db_file)
    )
    second = ingest_source_callgraph(
        source_callgraph=_SOURCE, source_key="app@1.0.0", db_file=str(db_file)
    )
    assert first["source_graph_id"] == second["source_graph_id"]
    graphs = execute_statement(
        "SELECT COUNT(*) AS c FROM SourceGraphs", db_file=str(db_file)
    )
    assert graphs[0]["c"] == 1
