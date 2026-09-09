"""Archive-member ingestion tests (P4.3)."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from blint_db.ingest import extract_archive_members, _seed_object_file_functions

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _write_minimal_archive(path: Path, members: list[tuple[str, bytes]]) -> None:
    """Write a System V/GNU `ar` archive by hand: header is 60 fixed bytes."""
    with open(path, "wb") as handle:
        handle.write(b"!<arch>\n")
        for name, data in members:
            # name(16) mtime(12) uid(6) gid(6) mode(8) size(10) magic(2)
            header = f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n"
            handle.write(header.encode("ascii"))
            handle.write(data)
            if len(data) % 2:
                handle.write(b"\n")


def test_extract_archive_members_skips_symbol_index_and_keeps_objects(tmp_path):
    archive = tmp_path / "libdemo.a"
    _write_minimal_archive(
        archive,
        [
            ("__.SYMDEF SORTED", b"index-bytes"),
            ("add.o", b"\xcf\xfa\xed\xfe" + b"add"),
            ("sub.o", b"\xcf\xfa\xed\xfe" + b"sub"),
            ("note.txt", b"not an object"),
        ],
    )
    members = extract_archive_members(str(archive))
    assert [m["name"] for m in members] == ["add.o", "sub.o"]
    assert members[0]["data"] == b"\xcf\xfa\xed\xfe" + b"add"


def test_extract_archive_members_basenames_windows_separated_names(tmp_path):
    archive = tmp_path / "libwin.a"
    _write_minimal_archive(archive, [("dir\\add.o", b"payload")])
    members = extract_archive_members(str(archive))
    # The stored member name is a plain basename; no directory may travel
    # with it into the database.
    assert [m["name"] for m in members] == ["add.o"]


def _clang() -> str | None:
    for candidate in ("clang", "/opt/homebrew/opt/llvm@18/bin/clang"):
        try:
            result = subprocess.run(
                [candidate, "--version"], capture_output=True, check=False
            )
            if result.returncode == 0:
                return candidate
        except OSError:
            continue
    return None


def test_seed_object_file_functions_requires_macho_object(tmp_path):
    metadata = {"functions": [{"name": "existing"}]}
    assert _seed_object_file_functions(metadata, str(tmp_path / "x.o")) is False
    empty = {"binary_type": "MachO", "functions": []}
    assert _seed_object_file_functions(empty, str(tmp_path / "missing.o")) is False


@pytest.mark.skipif(_clang() is None, reason="clang not available")
def test_seed_recovers_macho_object_functions(tmp_path):
    clang = _clang()
    source = tmp_path / "two_fns.c"
    source.write_text(
        "int add(int a, int b) { return a + b; }\n"
        "int mul(int a, int b) { return a * b; }\n"
    )
    obj = tmp_path / "two_fns.o"
    subprocess.run(
        [clang, "-arch", "arm64" if sys.platform == "darwin" else "", "-O0", "-c", str(source), "-o", str(obj)],
        capture_output=True,
        check=False,
    )
    if not obj.exists():
        pytest.skip("object file build failed")
    from blint_db.handlers.blint_handler import collect_blint_metadata

    metadata = collect_blint_metadata(str(obj), disassemble=False)
    assert metadata.get("binary_type") == "MachO"
    # A relocatable Mach-O object has no function list from lief; what
    # prologue scanning found (if anything) is not real discovery.
    metadata["functions"] = []
    assert _seed_object_file_functions(metadata, str(obj)) is True
    names = [f["name"] for f in metadata["functions"]]
    assert "_add" in names and "_mul" in names
    # MH_OBJECT seeding replaces any list, so a second run rewrites the same
    # seeds rather than appending.
    assert _seed_object_file_functions(metadata, str(obj)) is True
    assert [f["name"] for f in metadata["functions"]] == names
