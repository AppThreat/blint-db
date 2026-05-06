from pathlib import Path

from blint_db.handlers.language_handlers import homebrew_handler


def test_load_curated_homebrew_projects_reads_csv(tmp_path):
    csv_file = tmp_path / "homebrew-formulas.csv"
    csv_file.write_text(
        "formula,language_family,notes\nfmt,c++,Formatting library\nripgrep,rust,Rust CLI\n",
        encoding="utf-8",
    )

    assert homebrew_handler.load_curated_homebrew_projects(csv_file) == [
        "fmt",
        "ripgrep",
    ]


def test_default_curated_homebrew_projects_file_is_packaged_and_non_empty():
    assert (
        homebrew_handler.HOMEBREW_CURATED_FORMULAS_FILE.name == "homebrew-formulas.csv"
    )
    assert homebrew_handler.HOMEBREW_CURATED_FORMULAS_FILE.exists()

    projects = homebrew_handler.load_curated_homebrew_projects()

    assert "fmt" in projects
    assert "ripgrep" in projects
    assert "xcbeautify" in projects


def test_top_100_homebrew_projects_manifest_is_packaged_and_bounded():
    top_manifest = (
        homebrew_handler.HOMEBREW_CURATED_FORMULAS_FILE.parent
        / "homebrew-top-100-formulas.csv"
    )

    assert top_manifest.exists()

    projects = homebrew_handler.load_curated_homebrew_projects(top_manifest)

    assert len(projects) == 100
    assert projects[:5] == ["gh", "node", "awscli", "git", "ffmpeg"]


def test_homebrew_install_command_supports_source_reinstalls(monkeypatch):
    monkeypatch.setattr(
        homebrew_handler, "HOMEBREW_EXECUTABLE", "/opt/homebrew/bin/brew"
    )
    monkeypatch.setattr(homebrew_handler, "HOMEBREW_BUILD_FROM_SOURCE", True)
    monkeypatch.setattr(homebrew_handler, "HOMEBREW_REINSTALL_EXISTING", False)
    monkeypatch.setattr(homebrew_handler, "HOMEBREW_EXTRA_INSTALL_ARGS", ("--verbose",))

    command = homebrew_handler.homebrew_install_command("xcbeautify", installed=True)

    assert command == [
        "/opt/homebrew/bin/brew",
        "reinstall",
        "--formula",
        "--build-from-source",
        "--verbose",
        "xcbeautify",
    ]


def test_find_homebrew_artifacts_filters_non_binary_content(tmp_path, monkeypatch):
    keg_root = tmp_path / "Cellar" / "demo" / "1.0.0"
    (keg_root / "bin").mkdir(parents=True)
    (keg_root / "lib").mkdir()
    (keg_root / "share" / "doc").mkdir(parents=True)
    (keg_root / "include").mkdir()
    binary_file = keg_root / "bin" / "demo"
    symlink_file = keg_root / "bin" / "demo-link"
    library_file = keg_root / "lib" / "libdemo.a"
    readme_file = keg_root / "share" / "doc" / "README.md"
    header_file = keg_root / "include" / "demo.h"

    binary_file.write_bytes(b"\xcf\xfa\xed\xfebinary")
    symlink_file.symlink_to(binary_file)
    library_file.write_bytes(b"!<arch>\n")
    readme_file.write_text("documentation", encoding="utf-8")
    header_file.write_text("#pragma once", encoding="utf-8")

    monkeypatch.setattr(
        homebrew_handler,
        "is_exe",
        lambda path: str(path).endswith("/demo") or str(path).endswith("/demo-link"),
    )

    artifacts = homebrew_handler.find_homebrew_artifacts(keg_root)

    assert artifacts == [str(binary_file), str(library_file)]
