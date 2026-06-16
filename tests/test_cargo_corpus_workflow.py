"""Tests for the cargo source-callgraph corpus workflow.

These cover three additions: fetching the top crates from crates.io and writing
them to a CSV, resolving and invoking the rusi source analyzer, and wiring the
source callgraph into the cargo build pipeline so a binary can later be matched
against the source corpus.
"""

import csv
import os
import sys
from types import SimpleNamespace

from blint_db.handlers.language_handlers import cargo_handler, rusi_handler
from blint_db.handlers.sqlite_handler import (
    execute_statement,
    match_binary_against_source_corpus,
)
from blint_db.ingest import ingest_metadata
from blint_db.projects_compiler import cargo as cargo_compiler

_SOURCE_CALLGRAPH = {
    "tool": {"name": "rusi"},
    "schema_version": "0.1",
    "call_graph": {
        "nodes": [
            {"id": f"cg-{n}", "qualified_name": n, "local": True}
            for n in ("demo::main", "demo::helper", "demo::leaf")
        ],
        "edges": [
            {"source_id": "cg-demo::main", "target_id": "cg-demo::helper"},
            {"source_id": "cg-demo::helper", "target_id": "cg-demo::leaf"},
        ],
    },
}

_BINARY = {
    "file_path": "/tmp/demo",
    "name": "/tmp/demo",
    "llvm_target_tuple": "x86_64-unknown-linux-gnu",
    "callgraph": {
        "version": 2,
        "nodes": [
            {
                "id": 0,
                "key": "0x10::demo::main",
                "name": "demo::main",
                "address": "0x10",
            },
            {
                "id": 1,
                "key": "0x20::demo::helper",
                "name": "demo::helper",
                "address": "0x20",
            },
            {
                "id": 2,
                "key": "0x30::demo::leaf",
                "name": "demo::leaf",
                "address": "0x30",
            },
        ],
        "edges": [
            {"src": 0, "dst": 1, "kind": "direct", "confidence": "high"},
            {"src": 1, "dst": 2, "kind": "direct", "confidence": "high"},
        ],
    },
    "disassembled_functions": {
        "0x10::demo::main": {"name": "demo::main", "instruction_count": 12},
    },
}


def test_fetch_top_crates_parses_and_orders(monkeypatch):
    pages = {
        1: {
            "crates": [
                {"name": "serde", "max_stable_version": "1.0.0"},
                {"name": "syn", "newest_version": "2.0.0"},
                {"name": "noversion"},
            ]
        },
        2: {"crates": []},
    }
    calls = []

    def fake_api(url):
        calls.append(url)
        page = 2 if "page=2" in url else 1
        return pages[page]

    monkeypatch.setattr(cargo_handler, "_crates_api_json", fake_api)
    rows = cargo_handler.fetch_top_crates(10)

    names = [row["crate"] for row in rows]
    assert names == ["serde", "syn"]  # crate without a version is dropped
    assert rows[0]["version"] == "1.0.0"
    assert rows[1]["version"] == "2.0.0"
    assert any("sort=downloads" in url for url in calls)


def test_write_top_crates_csv_matches_curated_schema(monkeypatch, tmp_path):
    monkeypatch.setattr(
        cargo_handler,
        "_crates_api_json",
        lambda url: (
            {"crates": [{"name": "ripgrep", "max_stable_version": "14.1.1"}]}
            if "page=1" in url
            else {"crates": []}
        ),
    )
    out = tmp_path / "top.csv"
    written = cargo_handler.write_top_crates_csv(5, out)

    assert written == 1
    with open(out, encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["crate"] == "ripgrep"
    assert rows[0]["version"] == "14.1.1"
    # The file is loadable by the existing curated-crate loader.
    projects = cargo_handler.load_curated_cargo_projects(out)
    assert projects[0].crate == "ripgrep"
    assert projects[0].version == "14.1.1"


def test_resolve_rusi_command_prefers_argument(monkeypatch):
    monkeypatch.setattr(rusi_handler, "RUSI_COMMAND", "env-rusi --flag")
    assert rusi_handler.resolve_rusi_command("cargo run -p rusi-cli --") == [
        "cargo",
        "run",
        "-p",
        "rusi-cli",
        "--",
    ]
    assert rusi_handler.resolve_rusi_command(None) == ["env-rusi", "--flag"]
    monkeypatch.setattr(rusi_handler, "RUSI_COMMAND", "")
    assert rusi_handler.resolve_rusi_command(None) == []


def test_run_rusi_callgraph_invokes_command_and_reads_output(tmp_path):
    # A stub that behaves like rusi: it writes a callgraph to the --out path.
    stub = tmp_path / "fake_rusi.py"
    stub.write_text(
        "import json, sys\n"
        "args = sys.argv[1:]\n"
        "out = args[args.index('--out') + 1]\n"
        "json.dump({'call_graph': {'nodes': [], 'edges': []}}, open(out, 'w'))\n",
        encoding="utf-8",
    )
    source_dir = tmp_path / "src"
    source_dir.mkdir()

    rusi_command = f"{sys.executable} {stub}"
    result = rusi_handler.run_rusi_callgraph(
        source_dir, rusi_command=rusi_command, work_dir=tmp_path
    )
    assert result == {"call_graph": {"nodes": [], "edges": []}}


def test_run_rusi_callgraph_returns_none_without_command(tmp_path):
    assert rusi_handler.run_rusi_callgraph(tmp_path, rusi_command="") is None


def test_run_rusi_callgraph_handles_failing_command(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    # A command that exits non-zero and writes nothing.
    rusi_command = f'{sys.executable} -c "import sys; sys.exit(3)"'
    assert (
        rusi_handler.run_rusi_callgraph(
            source_dir, rusi_command=rusi_command, work_dir=tmp_path
        )
        is None
    )


def test_cargo_pipeline_ingests_source_callgraph_and_matches(monkeypatch, tmp_path):
    db_file = str(tmp_path / "blint-v2.db")
    source_root = tmp_path / "crate-src"
    source_root.mkdir()

    build_result = SimpleNamespace(
        spec=None,
        project_purl="pkg:cargo/demo@1.0.0",
        project_metadata={},
        build_metadata={},
        artifacts=[],  # no binaries; exercises the source-only path
        source_root=source_root,
        target_dir=tmp_path,
        target_triplet="x86_64-unknown-linux-gnu",
        target_os="linux",
        target_arch="x64",
        build_mode="release",
        optimization="release",
        strip_status="unknown",
    )
    monkeypatch.setattr(
        cargo_compiler, "build_cargo_project", lambda spec: build_result
    )
    monkeypatch.setattr(
        cargo_compiler, "run_rusi_callgraph", lambda *a, **k: _SOURCE_CALLGRAPH
    )

    spec = SimpleNamespace(crate="demo", selector="demo@1.0.0")
    cargo_compiler.add_project_cargo_db(
        spec,
        db_file=db_file,
        disassemble=False,
        with_source_callgraph=True,
        rusi_command="stub",
    )

    # The source graph was registered.
    graphs = execute_statement(
        "SELECT name, purl, tool FROM SourceGraphs", db_file=db_file
    )
    assert graphs[0]["purl"] == "pkg:cargo/demo@1.0.0"
    assert graphs[0]["tool"] == "rusi"

    # A separately ingested binary now matches that source graph in the corpus.
    binary = ingest_metadata(
        metadata=_BINARY, db_file=db_file, project_name="demo", build_system="manual"
    )
    matches = match_binary_against_source_corpus(binary["binary_id"], db_file=db_file)
    assert matches[0]["source_purl"] == "pkg:cargo/demo@1.0.0"
    assert matches[0]["shared_functions"] == 3
