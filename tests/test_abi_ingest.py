"""Ingest tests for the ELF ABI, runtime-loading and link-closure metadata.

These cover the data that has no equivalent in the dynamic dependency table: the
runtime floor derived from imported symbols, the libraries a binary opens on
demand, and the version node each symbol binds to. All three exist to make
component identification less ambiguous, so the tests check that they survive
ingest in a queryable form rather than only inside `metadata_json`.
"""

from blint_db.handlers.blint_handler import (
    extract_abi_requirements,
    extract_dependencies,
    extract_symbols,
)
from blint_db.handlers.sqlite_handler import (
    create_database,
    execute_statement,
    lookup_binaries_by_abi_requirement,
    lookup_project_symbol_matches,
    lookup_symbol_matches,
    lookup_versioned_symbol_matches,
)
from blint_db.ingest import ingest_metadata

# A minimal but realistic ELF metadata shape: two versioned imports at different
# glibc versions, a library opened at runtime, and one that is statically linked.
ELF_METADATA = {
    "name": "/usr/lib/libexample.so.1",
    "binary_type": "ELF",
    "exe_type": "genericbinary",
    "machine_type": "X86_64",
    "hashes": {"sha256": "a" * 64},
    "dynamic_entries": [
        {"tag": "NEEDED", "name": "libc.so.6", "value": 1},
        {"tag": "SONAME", "name": "libexample.so.1", "value": 14},
    ],
    "dynamic_symbols": [
        {
            "name": "statx",
            "version": "GLIBC_2.28",
            "is_imported": True,
            "is_function": True,
        },
        {
            "name": "memcpy",
            "version": "GLIBC_2.14",
            "is_imported": True,
            "is_function": True,
        },
        {
            "name": "example_init",
            "version": "",
            "is_exported": True,
            "is_function": True,
        },
        {
            # A C++ import: the demangled name is what a reader wants, the
            # linkage name is what another object's export table holds.
            "name": "APT::PackageContainer::begin()",
            "raw_name": "_ZN3APT16PackageContainer5beginEv",
            "version": "APTPKG_7.0",
            "is_imported": True,
            "is_function": True,
        },
    ],
    "abi_analysis": {
        "libc": "glibc",
        "min_glibc_version": "2.28",
        "uses_ifunc": False,
        "uses_private_symbol_versions": False,
        "requirements": [
            {
                "provider": "GLIBC",
                "min_version": "2.28",
                "symbol_count": 2,
                "determining_symbols": ["statx"],
                "package_name": "libc",
                "package_group": "gnu",
            }
        ],
    },
    "runtime_loading": {"entry_points": ["dlopen"], "loads_libraries": True},
    "recovered_dependencies": [
        {"name": "libvulkan.so.1", "confidence": "high", "evidence": ["imports dlopen"]}
    ],
    "dlopen_dependencies": [{"name": "libgpm.so.2", "priority": "recommended"}],
    "link_closure": {
        "resolved": [
            {"name": "libc.so.6", "path": "/lib/libc.so.6", "relation": "direct"}
        ],
        "missing": [{"name": "libmissing.so.3", "needed_by": "libexample.so.1"}],
    },
}


def ingest(tmp_path):
    db_file = str(tmp_path / "abi.db")
    create_database(db_file)
    ingest_metadata(
        metadata=ELF_METADATA,
        project_name="example",
        project_purl="pkg:generic/example@1.0",
        ecosystem="generic",
        db_file=db_file,
    )
    return db_file


def test_abi_requirements_are_extracted():
    requirements = extract_abi_requirements(ELF_METADATA)
    assert len(requirements) == 1
    assert requirements[0]["provider"] == "GLIBC"
    # The floor is the highest node bound, not the lowest and not the count.
    assert requirements[0]["min_version"] == "2.28"
    assert requirements[0]["determining_symbols"] == ["statx"]


def test_symbols_carry_their_version_node():
    symbols = {s["name"]: s for s in extract_symbols(ELF_METADATA)}
    assert symbols["statx"]["symbol_version"] == "GLIBC_2.28"
    assert symbols["memcpy"]["symbol_version"] == "GLIBC_2.14"
    # An unversioned symbol stores nothing rather than an empty string, so the
    # column stays null and the index stays small.
    assert symbols["example_init"]["symbol_version"] is None


def test_runtime_loaded_dependencies_are_ingested():
    sources = {dep["source"]: dep for dep in extract_dependencies(ELF_METADATA)}
    # Declared through the packaging note, and previously dropped entirely.
    assert sources["dlopen_dependencies"]["name"] == "libgpm.so.2"
    # Recovered from the image, which is the only source for most binaries.
    assert sources["recovered_dependencies"]["name"] == "libvulkan.so.1"
    assert sources["recovered_dependencies"]["tag"] == "high"
    assert sources["link_closure"]["name"] == "libc.so.6"
    assert sources["link_closure_missing"]["name"] == "libmissing.so.3"


def test_binary_row_carries_denormalized_abi_columns(tmp_path):
    db_file = ingest(tmp_path)
    rows = execute_statement(
        "SELECT libc, min_glibc_version, uses_ifunc, uses_runtime_loading FROM Binaries",
        db_file=db_file,
    )
    assert len(rows) == 1
    assert rows[0]["libc"] == "glibc"
    assert rows[0]["min_glibc_version"] == "2.28"
    assert rows[0]["uses_ifunc"] == 0
    assert rows[0]["uses_runtime_loading"] == 1


def test_abi_requirement_rows_are_queryable(tmp_path):
    db_file = ingest(tmp_path)
    matches = lookup_binaries_by_abi_requirement("GLIBC", db_file=db_file)
    assert len(matches) == 1
    assert matches[0]["min_version"] == "2.28"
    assert matches[0]["determining_symbols"] == "statx"
    # Filtering by floor is the query this table exists for.
    assert lookup_binaries_by_abi_requirement("GLIBC", min_version="2.17", db_file=db_file)
    assert not lookup_binaries_by_abi_requirement(
        "GLIBC", min_version="2.34", db_file=db_file
    )


def test_abi_floor_filter_orders_versions_numerically(tmp_path):
    db_file = ingest(tmp_path)
    # A lexical comparison would place 2.28 below 2.9 and wrongly exclude it.
    assert lookup_binaries_by_abi_requirement("GLIBC", min_version="2.9", db_file=db_file)


def test_versioned_symbol_lookup_distinguishes_versions(tmp_path):
    db_file = ingest(tmp_path)
    assert lookup_versioned_symbol_matches([("statx", "GLIBC_2.28")], db_file=db_file)
    # The same name at a version this binary does not bind is not a match, which
    # is the ambiguity a name-only lookup cannot resolve.
    assert not lookup_versioned_symbol_matches([("statx", "GLIBC_2.38")], db_file=db_file)
    assert lookup_versioned_symbol_matches([], db_file=db_file) == []


def test_linkage_name_is_stored_as_a_column():
    symbols = {s["name"]: s for s in extract_symbols(ELF_METADATA)}
    assert (
        symbols["APT::PackageContainer::begin()"]["raw_name"]
        == "_ZN3APT16PackageContainer5beginEv"
    )
    # Recorded only when demangling changed the name, so a plain C symbol
    # leaves the column null rather than duplicating itself into it.
    assert symbols["statx"]["raw_name"] is None


def test_symbol_lookup_matches_either_name_form(tmp_path):
    db_file = ingest(tmp_path)
    # A caller holding the demangled name finds it.
    assert lookup_symbol_matches(["APT::PackageContainer::begin()"], db_file=db_file)
    # So does a caller holding the linkage name, which is the form recovered
    # from another binary's export table.
    assert lookup_symbol_matches(["_ZN3APT16PackageContainer5beginEv"], db_file=db_file)
    assert lookup_project_symbol_matches(
        ["_ZN3APT16PackageContainer5beginEv"], db_file=db_file
    )
    assert not lookup_symbol_matches(["_ZN3APT16PackageContainer3endEv"], db_file=db_file)


def test_versioned_lookup_matches_the_linkage_name(tmp_path):
    db_file = ingest(tmp_path)
    assert lookup_versioned_symbol_matches(
        [("_ZN3APT16PackageContainer5beginEv", "APTPKG_7.0")], db_file=db_file
    )
    assert lookup_versioned_symbol_matches(
        [("APT::PackageContainer::begin()", "APTPKG_7.0")], db_file=db_file
    )
    # The same symbol at a version this binary does not bind is not a match.
    assert not lookup_versioned_symbol_matches(
        [("_ZN3APT16PackageContainer5beginEv", "APTPKG_8.0")], db_file=db_file
    )


def test_raw_name_column_is_populated_on_ingest(tmp_path):
    db_file = ingest(tmp_path)
    rows = execute_statement(
        "SELECT name, raw_name FROM Symbols WHERE raw_name IS NOT NULL",
        db_file=db_file,
    )
    assert [(row["name"], row["raw_name"]) for row in rows] == [
        ("APT::PackageContainer::begin()", "_ZN3APT16PackageContainer5beginEv")
    ]
