from enum import Enum

from blint_db.handlers.blint_handler import (
    extract_dependencies,
    extract_function_fingerprints,
    extract_symbols,
    sanitize_metadata,
    summarize_binary_metadata,
)
from blint_db.utils.json import canonical_json_dumps


class FakeCategory(Enum):
    LOCAL = "LOCAL"


def test_extract_symbols_collects_multiple_symbol_sources(isolated_metadata):
    symbols = extract_symbols(isolated_metadata)

    assert any(
        symbol["source"] == "functions" and symbol["name"] == "helper"
        for symbol in symbols
    )
    assert any(
        symbol["source"] == "exports" and symbol["name"] == "exported_api"
        for symbol in symbols
    )
    assert any(
        symbol["source"] == "imports" and symbol["name"] == "puts" for symbol in symbols
    )
    assert any(
        symbol["source"] == "dynamic_symbols" and symbol["name"] == "puts"
        for symbol in symbols
    )


def test_extract_dependencies_flattens_blint_v3_dependency_sources(isolated_metadata):
    dependencies = extract_dependencies(isolated_metadata)

    assert any(
        dep["source"] == "dynamic_entries" and dep["name"] == "libc.so.6"
        for dep in dependencies
    )
    assert any(
        dep["source"] == "libraries" and dep["name"] == "libdemo.so"
        for dep in dependencies
    )
    assert any(
        dep["source"] == "import_dependencies" and dep["name"] == "libc.so.6"
        for dep in dependencies
    )
    assert any(
        dep["source"] == "import_dependency_edges" and dep["name"] == "libc.so.6"
        for dep in dependencies
    )


def test_extract_function_fingerprints_keeps_hashes_and_metrics(isolated_metadata):
    functions = extract_function_fingerprints(isolated_metadata)

    assert functions == [
        {
            "function_key": "0x401000::helper",
            "name": "helper",
            "address": "0x401000",
            "rva_or_address": "0x1000",
            "assembly_hash": "a" * 64,
            "instruction_hash": "b" * 64,
            "instruction_count": 3,
            "function_type": "Has_Conditional_Jumps",
            "has_indirect_call": False,
            "has_pac": False,
            "has_system_call": False,
            "has_security_feature": True,
            "has_crypto_call": False,
            "has_gpu_call": False,
            "has_loop": False,
            "instruction_metrics": {
                "call_count": 1,
                "conditional_jump_count": 0,
                "xor_count": 0,
                "shift_count": 0,
                "arith_count": 1,
                "ret_count": 1,
                "jump_count": 0,
                "simd_fpu_count": 0,
                "unique_regs_read_count": 2,
                "unique_regs_written_count": 1,
            },
            "regs_read": ["rdi", "rip"],
            "regs_written": ["rax"],
            "used_simd_reg_types": [],
            "direct_calls": ["puts"],
            "direct_call_targets": [
                {"target_name": "puts", "kind": "direct", "raw_operand": "puts"},
            ],
            "proprietary_instructions": [],
            "sreg_interactions": [],
            "metadata": {
                "instructions_with_registers": [
                    {"position": 0, "regs_read": ["rdi"], "regs_written": ["rax"]},
                ]
            },
        }
    ]


def test_sanitize_metadata_drops_heavy_disassembly_payload(isolated_metadata):
    sanitized = sanitize_metadata(isolated_metadata)

    assert "disassembled_functions" not in sanitized
    assert "callgraph" in sanitized


def test_summarize_binary_metadata_aggregates_counts(isolated_metadata):
    summary = summarize_binary_metadata(isolated_metadata)

    assert summary["summary"]["function_count"] == 1
    assert summary["summary"]["imported_library_count"] >= 2
    assert summary["summary"]["symbol_count"] >= 5
    assert summary["symbols"]
    assert summary["dependencies"]
    assert summary["function_fingerprints"]


def test_sanitize_metadata_converts_enum_values_to_json_safe_strings(isolated_metadata):
    isolated_metadata["symtab_symbols"][0]["category"] = FakeCategory.LOCAL

    sanitized = sanitize_metadata(isolated_metadata)
    summary = summarize_binary_metadata(isolated_metadata)

    assert sanitized["symtab_symbols"][0]["category"] == "FakeCategory.LOCAL"
    canonical_json_dumps(summary["summary"])
