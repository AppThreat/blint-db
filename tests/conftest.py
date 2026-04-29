from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest


@pytest.fixture()
def sample_metadata():
    return {
        "file_path": "/tmp/demo/libdemo.so",
        "name": "/tmp/demo/libdemo.so",
        "binary_type": "ELF",
        "exe_type": "ELF64",
        "machine_type": "X86_64",
        "llvm_target_tuple": "x86_64-pc-linux-gnu",
        "is_shared_library": True,
        "hashes": {
            "md5": "m" * 32,
            "sha1": "1" * 40,
            "sha256": "2" * 64,
        },
        "build_info": {
            "language": "C",
            "compiler_version": "clang version 18.1.0",
            "linker_version": "GNU ld 2.42",
        },
        "security_properties": {
            "nx": True,
            "pie": True,
            "stripped": False,
        },
        "functions": [
            {"name": "helper", "address": "0x401000", "size": 16},
            {"name": "exported_api", "address": "0x401020", "size": 32},
        ],
        "ctor_functions": [
            {"name": "__init_array_start", "address": "0x400ff0", "size": 4},
        ],
        "imports": [
            {"name": "puts", "is_imported": True, "is_function": True},
        ],
        "exports": [
            {"name": "exported_api", "address": "0x401020", "size": 32},
        ],
        "symtab_symbols": [
            {"name": "helper", "address": "0x401000", "is_function": True},
            {
                "name": "exported_api",
                "address": "0x401020",
                "is_function": True,
                "is_exported": True,
            },
        ],
        "dynamic_symbols": [
            {"name": "puts", "is_imported": True, "is_function": True},
            {
                "name": "exported_api",
                "is_exported": True,
                "is_function": True,
                "address": "0x401020",
            },
        ],
        "dynamic_entries": [
            {"name": "libc.so.6", "tag": "NEEDED"},
        ],
        "libraries": [
            {"name": "libdemo.so", "version": "1.0.0", "tag": "SELF"},
        ],
        "import_dependencies": {
            "libraries": {
                "/tmp/demo/libdemo.so": {
                    "type": "main_binary",
                    "imports": ["puts"],
                    "imported_from": ["libc.so.6"],
                },
                "libc.so.6": {
                    "type": "library",
                    "exports": ["puts"],
                },
            },
            "dependencies": [
                {
                    "source": "/tmp/demo/libdemo.so",
                    "target": "libc.so.6",
                    "symbols": ["puts"],
                },
            ],
        },
        "disassembled_functions": {
            "0x401000::helper": {
                "name": "helper",
                "address": "0x401000",
                "rvaOrAddress": "0x1000",
                "assembly_hash": "a" * 64,
                "instruction_hash": "b" * 64,
                "instruction_count": 3,
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
                "direct_calls": ["puts"],
                "direct_call_targets": [
                    {"target_name": "puts", "kind": "direct", "raw_operand": "puts"},
                ],
                "has_indirect_call": False,
                "has_pac": False,
                "has_system_call": False,
                "has_security_feature": True,
                "has_crypto_call": False,
                "has_gpu_call": False,
                "has_loop": False,
                "regs_read": ["rdi", "rip"],
                "regs_written": ["rax"],
                "used_simd_reg_types": [],
                "instructions_with_registers": [
                    {"position": 0, "regs_read": ["rdi"], "regs_written": ["rax"]},
                ],
                "function_type": "Has_Conditional_Jumps",
                "proprietary_instructions": [],
                "sreg_interactions": [],
            }
        },
        "callgraph": {
            "version": 2,
            "node_count": 1,
            "edge_count": 0,
            "nodes": [
                {
                    "id": 0,
                    "key": "0x401000::helper",
                    "name": "helper",
                    "address": "0x401000",
                    "aliases": [],
                },
            ],
            "edges": [],
            "external": [
                {
                    "src": 0,
                    "target": "puts",
                    "count": 1,
                    "reason": "symbol_only_miss",
                    "confidence": "low",
                },
            ],
        },
    }


@pytest.fixture()
def sample_metadata_file(tmp_path: Path, sample_metadata):
    metadata_file = tmp_path / "libdemo-metadata.json"
    metadata_file.write_text(json.dumps(sample_metadata), encoding="utf-8")
    return metadata_file


@pytest.fixture()
def isolated_metadata(sample_metadata):
    return copy.deepcopy(sample_metadata)
