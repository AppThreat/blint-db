import json
from copy import deepcopy

from blint_db.handlers.sqlite_handler import (
    create_database,
    execute_statement,
    fetch_binary,
    get_schema_version,
    lookup_function_hash_matches,
    lookup_project_function_hash_matches,
    lookup_project_symbol_matches,
    lookup_symbol_matches,
)
from blint_db.ingest import ingest_metadata, ingest_metadata_file


def test_create_database_initializes_v2_schema(tmp_path):
    db_file = tmp_path / "blint-v2.db"

    create_database(str(db_file))

    assert get_schema_version(str(db_file)) == 2
    tables = {
        row["name"]
        for row in execute_statement(
            "SELECT name FROM sqlite_master WHERE type='table'",
            db_file=str(db_file),
        )
    }
    assert {
        "SchemaMeta",
        "Projects",
        "Builds",
        "Binaries",
        "Symbols",
        "Dependencies",
        "FunctionFingerprints",
    }.issubset(tables)


def test_ingest_metadata_stores_symbols_dependencies_and_hashes(
    tmp_path, isolated_metadata
):
    db_file = tmp_path / "blint-v2.db"

    result = ingest_metadata(
        metadata=isolated_metadata,
        db_file=str(db_file),
        project_name="demo",
        project_purl="pkg:generic/demo@1.0.0",
        ecosystem="manual",
        build_system="manual",
        target_os="linux",
        target_arch="x86_64",
        build_mode="release",
        build_metadata={"compiler": "clang"},
    )

    binary_row = fetch_binary(result["binary_id"], db_file=str(db_file))
    assert binary_row["project_name"] == "demo"
    assert binary_row["binary_name"] == "libdemo.so"

    binaries = execute_statement(
        "SELECT disassembly_enabled, symbol_count, function_count, imported_library_count, metadata_json FROM Binaries",
        db_file=str(db_file),
    )
    assert binaries[0]["disassembly_enabled"] == 1
    assert binaries[0]["symbol_count"] >= 5
    assert binaries[0]["function_count"] == 1
    assert binaries[0]["imported_library_count"] >= 2
    stored_metadata = json.loads(binaries[0]["metadata_json"])
    assert "disassembled_functions" not in stored_metadata
    assert stored_metadata["callgraph"]["version"] == 2

    symbols = execute_statement(
        "SELECT name, source FROM Symbols ORDER BY source, name",
        db_file=str(db_file),
    )
    assert any(
        row["name"] == "helper" and row["source"] == "functions" for row in symbols
    )
    assert any(row["name"] == "puts" and row["source"] == "imports" for row in symbols)

    dependencies = execute_statement(
        "SELECT name, source FROM Dependencies ORDER BY source, name",
        db_file=str(db_file),
    )
    assert any(
        row["name"] == "libc.so.6" and row["source"] == "dynamic_entries"
        for row in dependencies
    )

    functions = execute_statement(
        "SELECT name, assembly_hash, instruction_hash FROM FunctionFingerprints",
        db_file=str(db_file),
    )
    assert functions[0]["assembly_hash"] == "a" * 64
    assert functions[0]["instruction_hash"] == "b" * 64


def test_lookup_helpers_rank_symbol_and_hash_matches(tmp_path, isolated_metadata):
    db_file = tmp_path / "blint-v2.db"
    ingest_metadata(
        metadata=isolated_metadata,
        db_file=str(db_file),
        project_name="demo",
        project_purl="pkg:generic/demo@1.0.0",
        ecosystem="manual",
        build_system="manual",
    )

    symbol_matches = lookup_symbol_matches(["helper", "puts"], db_file=str(db_file))
    hash_matches = lookup_function_hash_matches(
        instruction_hashes=["b" * 64],
        db_file=str(db_file),
    )

    assert symbol_matches[0]["project_name"] == "demo"
    assert symbol_matches[0]["matched_symbol_count"] == 2
    assert hash_matches[0]["project_name"] == "demo"
    assert hash_matches[0]["matched_function_count"] == 1


def test_project_lookup_helpers_roll_up_matches_across_binaries(
    tmp_path, isolated_metadata
):
    db_file = tmp_path / "blint-v2.db"
    metadata_one = deepcopy(isolated_metadata)
    metadata_two = deepcopy(isolated_metadata)
    metadata_three = deepcopy(isolated_metadata)

    metadata_two["file_path"] = "/tmp/demo/libdemo-helper.so"
    metadata_two["name"] = "/tmp/demo/libdemo-helper.so"
    metadata_two["functions"] = [
        {"name": "helper_two", "address": "0x402000", "size": 24},
        {"name": "puts", "address": "0x402040", "size": 16},
    ]
    metadata_two["imports"] = [
        {"name": "puts", "is_imported": True, "is_function": True},
        {"name": "strlen", "is_imported": True, "is_function": True},
    ]
    metadata_two["symtab_symbols"] = [
        {"name": "helper_two", "address": "0x402000", "is_function": True},
        {"name": "strlen", "is_imported": True, "is_function": True},
    ]
    metadata_two["dynamic_symbols"] = [
        {"name": "puts", "is_imported": True, "is_function": True},
        {"name": "strlen", "is_imported": True, "is_function": True},
    ]
    metadata_two["disassembled_functions"] = {
        "0x402000::helper_two": {
            **deepcopy(
                next(iter(isolated_metadata["disassembled_functions"].values()))
            ),
            "name": "helper_two",
            "address": "0x402000",
            "rvaOrAddress": "0x2000",
            "assembly_hash": "c" * 64,
            "instruction_hash": "d" * 64,
        }
    }

    metadata_three["file_path"] = "/tmp/other/libother.so"
    metadata_three["name"] = "/tmp/other/libother.so"
    metadata_three["functions"] = [
        {"name": "helper", "address": "0x501000", "size": 12},
    ]
    metadata_three["imports"] = [
        {"name": "puts", "is_imported": True, "is_function": True},
    ]
    metadata_three["symtab_symbols"] = [
        {"name": "helper", "address": "0x501000", "is_function": True},
    ]
    metadata_three["dynamic_symbols"] = [
        {"name": "puts", "is_imported": True, "is_function": True},
    ]
    metadata_three["disassembled_functions"] = {
        "0x501000::helper": {
            **deepcopy(
                next(iter(isolated_metadata["disassembled_functions"].values()))
            ),
            "name": "helper",
            "address": "0x501000",
            "rvaOrAddress": "0x3000",
            "assembly_hash": "e" * 64,
            "instruction_hash": "f" * 64,
        }
    }

    ingest_metadata(
        metadata=metadata_one,
        db_file=str(db_file),
        project_name="demo",
        project_purl="pkg:generic/demo@1.0.0",
        ecosystem="manual",
        build_system="manual",
    )
    ingest_metadata(
        metadata=metadata_two,
        db_file=str(db_file),
        project_name="demo",
        project_purl="pkg:generic/demo@1.0.0",
        ecosystem="manual",
        build_system="manual",
    )
    ingest_metadata(
        metadata=metadata_three,
        db_file=str(db_file),
        project_name="other",
        project_purl="pkg:generic/other@2.0.0",
        ecosystem="manual",
        build_system="manual",
    )

    binary_symbol_matches = lookup_symbol_matches(
        ["helper", "helper_two", "puts", "strlen"],
        db_file=str(db_file),
    )
    project_symbol_matches = lookup_project_symbol_matches(
        ["helper", "helper_two", "puts", "strlen"],
        db_file=str(db_file),
    )
    binary_hash_matches = lookup_function_hash_matches(
        instruction_hashes=["b" * 64, "d" * 64],
        db_file=str(db_file),
    )
    project_hash_matches = lookup_project_function_hash_matches(
        instruction_hashes=["b" * 64, "d" * 64],
        db_file=str(db_file),
    )

    assert binary_symbol_matches[0]["project_name"] == "demo"
    assert binary_symbol_matches[0]["matched_symbol_count"] >= 2
    assert {row["binary_name"] for row in binary_symbol_matches[:2]} == {
        "libdemo.so",
        "libdemo-helper.so",
    }

    assert project_symbol_matches[0]["project_name"] == "demo"
    assert project_symbol_matches[0]["project_purl"] == "pkg:generic/demo@1.0.0"
    assert project_symbol_matches[0]["matched_binary_count"] == 2
    assert project_symbol_matches[0]["matched_symbol_count"] == 4
    assert project_symbol_matches[1]["project_name"] == "other"

    assert {row["binary_name"] for row in binary_hash_matches[:2]} == {
        "libdemo.so",
        "libdemo-helper.so",
    }
    assert project_hash_matches[0]["project_name"] == "demo"
    assert project_hash_matches[0]["project_purl"] == "pkg:generic/demo@1.0.0"
    assert project_hash_matches[0]["matched_binary_count"] == 2
    assert project_hash_matches[0]["matched_function_count"] == 2


def test_ingest_metadata_file_supports_precomputed_blint_json(
    tmp_path, sample_metadata_file
):
    db_file = tmp_path / "blint-v2.db"

    result = ingest_metadata_file(
        str(sample_metadata_file),
        db_file=str(db_file),
        project_name="demo-json",
        project_purl="pkg:generic/demo-json@1.0.0",
        ecosystem="manual",
        build_system="manual",
        target_os="linux",
        target_arch="x86_64",
        build_mode="debug",
    )

    binary_row = fetch_binary(result["binary_id"], db_file=str(db_file))
    assert binary_row["project_name"] == "demo-json"
    assert binary_row["project_purl"] == "pkg:generic/demo-json@1.0.0"
