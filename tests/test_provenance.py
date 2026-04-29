import json

from blint_db.handlers.sqlite_handler import create_database
from blint_db.utils import provenance


def test_default_run_metadata_path_uses_metadata_json_suffix(tmp_path):
    assert (
        provenance.default_run_metadata_path(tmp_path / "blint.db")
        == tmp_path / "blint.metadata.json"
    )
    assert (
        provenance.default_run_metadata_path(tmp_path / "blint-v2")
        == tmp_path / "blint-v2.metadata.json"
    )


def test_write_run_metadata_records_database_counts_and_selection(
    tmp_path, monkeypatch
):
    db_file = tmp_path / "blint.db"
    create_database(str(db_file))

    monkeypatch.setattr(
        provenance,
        "_tool_versions",
        lambda: {"python": "3.13.2", "meson": "1.11.1"},
    )
    monkeypatch.setattr(
        provenance,
        "_package_metadata",
        lambda package_name: {"version": f"{package_name}-version"},
    )
    monkeypatch.setattr(
        provenance,
        "_git_repo_metadata",
        lambda path, expected_commit=None: {
            "path": str(path),
            "commit": expected_commit or "deadbeef",
            "expected_commit": expected_commit,
            "dirty": False,
        },
    )

    metadata_path = provenance.write_run_metadata(
        command="build-vcpkg",
        db_file=str(db_file),
        disassemble=True,
        test_mode=True,
        selected_projects=["zlib", "bzip2"],
    )

    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata_path.name == "blint.metadata.json"
    assert payload["run"]["command"] == "build-vcpkg"
    assert payload["run"]["disassemble"] is True
    assert payload["run"]["test_mode"] is True
    assert payload["run"]["selected_projects"] == ["zlib", "bzip2"]
    assert payload["database"]["table_counts"]["Projects"] == 0
    assert payload["database"]["table_counts"]["Binaries"] == 0
    assert payload["tool_versions"]["meson"] == "1.11.1"
    assert (
        payload["repositories"]["vcpkg"]["expected_commit"]
        == provenance.VCPKG_COMMIT_HASH
    )


def test_write_run_metadata_records_homebrew_context(tmp_path, monkeypatch):
    db_file = tmp_path / "blint.db"
    create_database(str(db_file))

    monkeypatch.setattr(
        provenance,
        "_tool_versions",
        lambda: {"python": "3.13.2", "brew": "Homebrew 4.6.0"},
    )
    monkeypatch.setattr(
        provenance,
        "_package_metadata",
        lambda package_name: {"version": f"{package_name}-version"},
    )
    monkeypatch.setattr(
        provenance,
        "_git_repo_metadata",
        lambda path, expected_commit=None: {
            "path": str(path),
            "commit": expected_commit or "deadbeef",
            "expected_commit": expected_commit,
            "dirty": False,
        },
    )
    monkeypatch.setattr(
        provenance,
        "_homebrew_repository_path",
        lambda tap=None: "/opt/homebrew"
        if tap is None
        else "/opt/homebrew/Library/Taps/homebrew/homebrew-core",
    )
    monkeypatch.setattr(
        provenance,
        "_homebrew_prefix",
        lambda flag: "/opt/homebrew" if flag == "--prefix" else "/opt/homebrew/Cellar",
    )

    metadata_path = provenance.write_run_metadata(
        command="build-homebrew",
        db_file=str(db_file),
        selected_projects=["zstd", "xcbeautify"],
    )

    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert payload["run"]["command"] == "build-homebrew"
    assert (
        payload["ecosystem_sources"]["homebrew"]["core_tap"]
        == provenance.HOMEBREW_CORE_TAP
    )
    assert (
        payload["ecosystem_sources"]["homebrew"]["build_from_source"]
        == provenance.HOMEBREW_BUILD_FROM_SOURCE
    )
    assert sorted(payload["repositories"].keys()) == [
        "blint-db",
        "homebrew-brew",
        "homebrew-core",
    ]


def test_write_run_metadata_records_cargo_context(tmp_path, monkeypatch):
    db_file = tmp_path / "blint.db"
    create_database(str(db_file))

    monkeypatch.setattr(
        provenance,
        "_tool_versions",
        lambda: {
            "python": "3.13.2",
            "cargo": "cargo 1.91.1",
            "rustc": "rustc 1.91.1",
        },
    )
    monkeypatch.setattr(
        provenance,
        "_package_metadata",
        lambda package_name: {"version": f"{package_name}-version"},
    )
    monkeypatch.setattr(
        provenance,
        "_git_repo_metadata",
        lambda path, expected_commit=None: {
            "path": str(path),
            "commit": expected_commit or "deadbeef",
            "expected_commit": expected_commit,
            "dirty": False,
        },
    )

    metadata_path = provenance.write_run_metadata(
        command="build-cargo",
        db_file=str(db_file),
        selected_projects=["choose@1.3.7", "hexyl@0.17.0"],
    )

    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert payload["run"]["command"] == "build-cargo"
    assert (
        payload["config"]["cargo_default_profile"] == provenance.CARGO_DEFAULT_PROFILE
    )
    assert payload["ecosystem_sources"]["cargo"]["curated_crates_file"] == str(
        provenance.CARGO_CURATED_CRATES_FILE
    )
    assert payload["ecosystem_sources"]["cargo"]["selected_crates"] == [
        "choose@1.3.7",
        "hexyl@0.17.0",
    ]


def test_write_run_metadata_records_conan_context(tmp_path, monkeypatch):
    db_file = tmp_path / "blint.db"
    create_database(str(db_file))

    monkeypatch.setattr(
        provenance,
        "_tool_versions",
        lambda: {
            "python": "3.13.2",
            "conan": "Conan version 2.15.0",
        },
    )
    monkeypatch.setattr(
        provenance,
        "_package_metadata",
        lambda package_name: {"version": f"{package_name}-version"},
    )
    monkeypatch.setattr(
        provenance,
        "_git_repo_metadata",
        lambda path, expected_commit=None: {
            "path": str(path),
            "commit": expected_commit or "deadbeef",
            "expected_commit": expected_commit,
            "dirty": False,
        },
    )

    metadata_path = provenance.write_run_metadata(
        command="build-conan",
        db_file=str(db_file),
        selected_projects=["fmt/11.2.0#shared-release", "zlib/1.3.1#static-debug"],
    )

    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert payload["run"]["command"] == "build-conan"
    assert (
        payload["config"]["conan_default_build_type"]
        == provenance.CONAN_DEFAULT_BUILD_TYPE
    )
    assert payload["ecosystem_sources"]["conan"]["curated_packages_file"] == str(
        provenance.CONAN_CURATED_PACKAGES_FILE
    )
    assert payload["ecosystem_sources"]["conan"]["selected_packages"] == [
        "fmt/11.2.0#shared-release",
        "zlib/1.3.1#static-debug",
    ]
