import json
from pathlib import Path

import pytest

from blint_db.cli import (
    _resolve_command,
    build_parser,
    cargo_add_blint_bom_process,
    conan_add_blint_bom_process,
    homebrew_add_blint_bom_process,
    main,
    meson_add_blint_bom_process,
    vcpkg_add_blint_bom_process,
)
from blint_db.handlers.sqlite_handler import execute_statement


def test_build_parser_exposes_v2_ingest_and_disassembly_flags():
    parser = build_parser()
    args = parser.parse_args(
        [
            "--db-file",
            "demo.db",
            "--disassemble",
            "ingest",
            "--metadata-file",
            "demo.json",
            "--project-name",
            "demo",
        ]
    )

    assert args.db_file == "demo.db"
    assert args.disassemble is True
    assert args.command == "ingest"
    assert args.metadata_file == "demo.json"
    assert args.project_name == "demo"


def test_legacy_meson_and_vcpkg_aliases_still_parse():
    parser = build_parser()

    meson_args = parser.parse_args(["-Z1", "--clean-start"])
    vcpkg_args = parser.parse_args(["-Z2", "--clean-start"])

    assert meson_args.meson is True
    assert vcpkg_args.vcpkg is True
    assert meson_args.clean is True
    assert vcpkg_args.clean is True


def test_resolve_command_supports_build_subcommands_without_ingest_flags():
    parser = build_parser()
    args = parser.parse_args(["build-meson"])

    assert _resolve_command(args) == "build-meson"


def test_build_meson_subcommand_accepts_project_selection_flags_after_command():
    parser = build_parser()
    args = parser.parse_args(["build-meson", "-s", "zstd", "bzip2", "-f"])

    assert args.command == "build-meson"
    assert args.sel_project == ["zstd", "bzip2"]
    assert args.test_mode is True
    assert args.remove_after_build is True


def test_build_meson_subcommand_can_retain_artifacts():
    parser = build_parser()
    args = parser.parse_args(["build-meson", "--retain-build-artifacts", "-s", "zlib"])

    assert args.command == "build-meson"
    assert args.remove_after_build is False


def test_build_homebrew_subcommand_accepts_project_selection_flags_after_command():
    parser = build_parser()
    args = parser.parse_args(["build-homebrew", "-s", "ripgrep", "xcbeautify", "-f"])

    assert args.command == "build-homebrew"
    assert args.sel_project == ["ripgrep", "xcbeautify"]
    assert args.test_mode is True


def test_build_cargo_subcommand_accepts_project_selection_flags_after_command():
    parser = build_parser()
    args = parser.parse_args(
        ["build-cargo", "-s", "choose@1.3.7#default", "hexyl@0.17.0#clipboard", "-f"]
    )

    assert args.command == "build-cargo"
    assert args.sel_project == ["choose@1.3.7#default", "hexyl@0.17.0#clipboard"]
    assert args.test_mode is True


def test_build_conan_subcommand_accepts_project_selection_flags_after_command():
    parser = build_parser()
    args = parser.parse_args(
        [
            "build-conan",
            "-s",
            "fmt/11.2.0#shared-release",
            "zlib/1.3.1#static-debug",
            "-f",
        ]
    )

    assert args.command == "build-conan"
    assert args.sel_project == [
        "fmt/11.2.0#shared-release",
        "zlib/1.3.1#static-debug",
    ]
    assert args.test_mode is True


def test_build_cargo_subcommand_preserves_global_few_packages_flag_before_command():
    parser = build_parser()
    args = parser.parse_args(["-f", "build-cargo"])

    assert args.command == "build-cargo"
    assert args.test_mode is True


def test_meson_add_blint_bom_process_resolves_selected_projects(monkeypatch):
    built_projects = []
    removed_projects = []

    monkeypatch.setattr(
        "blint_db.cli.get_wrapdb_projects",
        lambda: [("bzip2", "/tmp/bzip2.wrap"), ("zstd", "/tmp/zstd.wrap")],
    )
    monkeypatch.setattr(
        "blint_db.cli.mt_meson_blint_db_build",
        lambda project_tuple, **kwargs: built_projects.append(project_tuple) or [],
    )
    monkeypatch.setattr(
        "blint_db.cli.remove_wrapdb_project",
        lambda project_name: removed_projects.append(project_name),
    )

    meson_add_blint_bom_process(
        db_file="demo.db",
        sel_project=["zstd"],
    )

    assert built_projects == [("zstd", "/tmp/zstd.wrap")]
    assert removed_projects == ["zstd"]


def test_meson_add_blint_bom_process_can_retain_artifacts(monkeypatch):
    built_projects = []
    removed_projects = []

    monkeypatch.setattr(
        "blint_db.cli.get_wrapdb_projects",
        lambda: [("zstd", "/tmp/zstd.wrap")],
    )
    monkeypatch.setattr(
        "blint_db.cli.mt_meson_blint_db_build",
        lambda project_tuple, **kwargs: built_projects.append(project_tuple) or [],
    )
    monkeypatch.setattr(
        "blint_db.cli.remove_wrapdb_project",
        lambda project_name: removed_projects.append(project_name),
    )

    meson_add_blint_bom_process(
        db_file="demo.db",
        sel_project=["zstd"],
        remove_after_build=False,
    )

    assert built_projects == [("zstd", "/tmp/zstd.wrap")]
    assert removed_projects == []


def test_meson_add_blint_bom_process_collects_project_outcomes(monkeypatch):
    monkeypatch.setattr(
        "blint_db.cli.get_wrapdb_projects",
        lambda: [("zstd", "/tmp/zstd.wrap")],
    )

    def _fake_builder(project_tuple, **kwargs):
        kwargs["project_outcomes"].append(
            {
                "selector": project_tuple[0],
                "project_name": project_tuple[0],
                "ecosystem": "wrapdb",
                "build_system": "meson",
                "status": "build_failed",
                "artifact_count": 0,
                "failure": {"stage": "build", "message": "compile failed"},
            }
        )
        return []

    monkeypatch.setattr("blint_db.cli.mt_meson_blint_db_build", _fake_builder)
    monkeypatch.setattr("blint_db.cli.remove_wrapdb_project", lambda project_name: None)

    outcomes = meson_add_blint_bom_process(db_file="demo.db", sel_project=["zstd"])

    assert outcomes == [
        {
            "selector": "zstd",
            "project_name": "zstd",
            "ecosystem": "wrapdb",
            "build_system": "meson",
            "status": "build_failed",
            "artifact_count": 0,
            "failure": {"stage": "build", "message": "compile failed"},
        }
    ]


def test_meson_add_blint_bom_process_rejects_unknown_selected_projects(monkeypatch):
    monkeypatch.setattr(
        "blint_db.cli.get_wrapdb_projects",
        lambda: [("bzip2", "/tmp/bzip2.wrap")],
    )

    with pytest.raises(SystemExit, match="Unknown wrapdb project"):
        meson_add_blint_bom_process(db_file="demo.db", sel_project=["missing"])


def test_vcpkg_add_blint_bom_process_resolves_selected_projects(tmp_path, monkeypatch):
    built_projects = []
    removed_projects = []

    monkeypatch.setattr(
        "blint_db.cli.get_vcpkg_projects",
        lambda: ["bzip2", "zlib"],
    )
    monkeypatch.setattr(
        "blint_db.cli.mt_vcpkg_blint_db_build",
        lambda project_name, vcpkg_json, **kwargs: built_projects.append(
            (project_name, str(vcpkg_json))
        )
        or [],
    )
    monkeypatch.setattr(
        "blint_db.cli.remove_vcpkg_project",
        lambda project_name: removed_projects.append(project_name),
    )
    monkeypatch.setattr("blint_db.cli.VCPKG_LOCATION", Path(tmp_path))

    vcpkg_add_blint_bom_process(db_file="demo.db", sel_project=["zlib"])

    assert built_projects == [
        ("zlib", str(Path(tmp_path) / "ports" / "zlib" / "vcpkg.json"))
    ]
    assert removed_projects == ["zlib"]


def test_vcpkg_add_blint_bom_process_can_retain_artifacts(tmp_path, monkeypatch):
    built_projects = []
    removed_projects = []

    monkeypatch.setattr(
        "blint_db.cli.get_vcpkg_projects",
        lambda: ["zlib"],
    )
    monkeypatch.setattr(
        "blint_db.cli.mt_vcpkg_blint_db_build",
        lambda project_name, vcpkg_json, **kwargs: built_projects.append(
            (project_name, str(vcpkg_json))
        )
        or [],
    )
    monkeypatch.setattr(
        "blint_db.cli.remove_vcpkg_project",
        lambda project_name: removed_projects.append(project_name),
    )
    monkeypatch.setattr("blint_db.cli.VCPKG_LOCATION", Path(tmp_path))

    vcpkg_add_blint_bom_process(
        db_file="demo.db",
        sel_project=["zlib"],
        remove_after_build=False,
    )

    assert built_projects == [
        ("zlib", str(Path(tmp_path) / "ports" / "zlib" / "vcpkg.json"))
    ]
    assert removed_projects == []


def test_vcpkg_add_blint_bom_process_rejects_unknown_selected_projects(monkeypatch):
    monkeypatch.setattr(
        "blint_db.cli.get_vcpkg_projects",
        lambda: ["bzip2"],
    )

    with pytest.raises(SystemExit, match="Unknown vcpkg project"):
        vcpkg_add_blint_bom_process(db_file="demo.db", sel_project=["missing"])


def test_homebrew_add_blint_bom_process_uses_curated_test_subset(monkeypatch):
    built_projects = []

    monkeypatch.setattr(
        "blint_db.cli.load_curated_homebrew_projects",
        lambda: ["zstd", "ripgrep"],
    )
    monkeypatch.setattr(
        "blint_db.cli.mt_homebrew_blint_db_build",
        lambda formula_name, **kwargs: built_projects.append(formula_name) or [],
    )

    homebrew_add_blint_bom_process(db_file="demo.db", test_mode=True)

    assert built_projects == ["zstd", "ripgrep"]


def test_homebrew_add_blint_bom_process_rejects_unknown_selected_projects(monkeypatch):
    monkeypatch.setattr(
        "blint_db.cli.get_homebrew_projects",
        lambda: ["zstd", "ripgrep"],
    )

    with pytest.raises(SystemExit, match="Unknown Homebrew formula"):
        homebrew_add_blint_bom_process(db_file="demo.db", sel_project=["missing"])


def test_homebrew_add_blint_bom_process_rejects_empty_curated_subset(monkeypatch):
    monkeypatch.setattr("blint_db.cli.load_curated_homebrew_projects", lambda: [])
    monkeypatch.setattr(
        "blint_db.cli.HOMEBREW_CURATED_FORMULAS_FILE",
        Path("/tmp/homebrew-formulas.csv"),
    )

    with pytest.raises(SystemExit, match="curated Homebrew input file"):
        homebrew_add_blint_bom_process(db_file="demo.db", test_mode=True)


def test_cargo_add_blint_bom_process_uses_curated_test_subset(monkeypatch):
    built_projects = []
    curated_projects = [
        type("Spec", (), {"selector": "choose@1.3.7"})(),
        type("Spec", (), {"selector": "b3sum@1.8.5"})(),
        type("Spec", (), {"selector": "hexyl@0.17.0"})(),
    ]

    monkeypatch.setattr("blint_db.cli.CARGO_FEW_PACKAGES", 2)
    monkeypatch.setattr(
        "blint_db.cli.load_curated_cargo_projects",
        lambda: curated_projects,
    )
    monkeypatch.setattr(
        "blint_db.cli.mt_cargo_blint_db_build",
        lambda project_spec, **kwargs: built_projects.append(project_spec.selector)
        or [],
    )

    cargo_add_blint_bom_process(db_file="demo.db", test_mode=True)

    assert built_projects == ["choose@1.3.7", "b3sum@1.8.5"]


def test_cargo_add_blint_bom_process_resolves_selected_projects(monkeypatch):
    built_projects = []
    curated_projects = [
        type(
            "Spec",
            (),
            {"selector": "choose@1.3.7", "crate": "choose", "version": "1.3.7"},
        )(),
    ]

    monkeypatch.setattr(
        "blint_db.cli.get_cargo_projects",
        lambda: curated_projects,
    )
    monkeypatch.setattr(
        "blint_db.cli.resolve_cargo_project_spec",
        lambda selector, curated_projects=None: curated_projects[0]
        if selector == "choose"
        else (_ for _ in ()).throw(ValueError("missing")),
    )
    monkeypatch.setattr(
        "blint_db.cli.mt_cargo_blint_db_build",
        lambda project_spec, **kwargs: built_projects.append(project_spec.selector)
        or [],
    )

    cargo_add_blint_bom_process(db_file="demo.db", sel_project=["choose"])

    assert built_projects == ["choose@1.3.7"]


def test_conan_add_blint_bom_process_uses_curated_test_subset(monkeypatch):
    built_projects = []
    curated_projects = [
        type("Spec", (), {"selector": "fmt/11.2.0#shared-release"})(),
        type("Spec", (), {"selector": "zlib/1.3.1#shared-release"})(),
        type("Spec", (), {"selector": "openssl/3.5.0#shared-release"})(),
    ]

    monkeypatch.setattr("blint_db.cli.CONAN_FEW_PACKAGES", 2)
    monkeypatch.setattr(
        "blint_db.cli.load_curated_conan_projects",
        lambda: curated_projects,
    )
    monkeypatch.setattr(
        "blint_db.cli.mt_conan_blint_db_build",
        lambda project_spec, **kwargs: built_projects.append(project_spec.selector)
        or [],
    )

    conan_add_blint_bom_process(db_file="demo.db", test_mode=True)

    assert built_projects == ["fmt/11.2.0#shared-release", "zlib/1.3.1#shared-release"]


def test_conan_add_blint_bom_process_resolves_selected_projects(monkeypatch):
    built_projects = []
    curated_projects = [
        type(
            "Spec",
            (),
            {
                "selector": "fmt/11.2.0#shared-release",
                "reference": "fmt/11.2.0",
                "configuration": "shared-release",
                "name": "fmt",
            },
        )(),
    ]

    monkeypatch.setattr(
        "blint_db.cli.load_curated_conan_projects",
        lambda: curated_projects,
    )
    monkeypatch.setattr(
        "blint_db.cli.resolve_conan_project_spec",
        lambda selector, curated_projects=None: curated_projects[0]
        if selector == "fmt"
        else (_ for _ in ()).throw(ValueError("missing")),
    )
    monkeypatch.setattr(
        "blint_db.cli.mt_conan_blint_db_build",
        lambda project_spec, **kwargs: built_projects.append(project_spec.selector)
        or [],
    )

    conan_add_blint_bom_process(db_file="demo.db", sel_project=["fmt"])

    assert built_projects == ["fmt/11.2.0#shared-release"]


def test_conan_add_blint_bom_process_rejects_empty_curated_subset(monkeypatch):
    monkeypatch.setattr("blint_db.cli.load_curated_conan_projects", lambda: [])
    monkeypatch.setattr(
        "blint_db.cli.CONAN_CURATED_PACKAGES_FILE",
        Path("/tmp/conan-center-packages.csv"),
    )

    with pytest.raises(SystemExit, match="curated Conan input file"):
        conan_add_blint_bom_process(db_file="demo.db", test_mode=True)


def test_conan_add_blint_bom_process_rejects_unknown_selected_projects(monkeypatch):
    monkeypatch.setattr(
        "blint_db.cli.load_curated_conan_projects",
        lambda: [
            type(
                "Spec",
                (),
                {
                    "selector": "fmt/11.2.0#shared-release",
                    "reference": "fmt/11.2.0",
                    "configuration": "shared-release",
                    "name": "fmt",
                },
            )()
        ],
    )

    with pytest.raises(SystemExit, match="Unknown Conan package"):
        conan_add_blint_bom_process(db_file="demo.db", sel_project=["missing"])


def test_cargo_add_blint_bom_process_rejects_empty_curated_subset(monkeypatch):
    monkeypatch.setattr("blint_db.cli.load_curated_cargo_projects", lambda: [])
    monkeypatch.setattr(
        "blint_db.cli.CARGO_CURATED_CRATES_FILE",
        Path("/tmp/cargo-crates.csv"),
    )

    with pytest.raises(SystemExit, match="curated Cargo input file"):
        cargo_add_blint_bom_process(db_file="demo.db", test_mode=True)


def test_cargo_add_blint_bom_process_rejects_unknown_selected_projects(monkeypatch):
    monkeypatch.setattr("blint_db.cli.get_cargo_projects", lambda: [])

    with pytest.raises(SystemExit, match="Unknown cargo crate"):
        cargo_add_blint_bom_process(db_file="demo.db", sel_project=["missing"])


def test_main_ingests_metadata_file_from_cli(
    tmp_path, sample_metadata_file, monkeypatch, capsys
):
    db_file = tmp_path / "cli-ingest.db"
    monkeypatch.setattr(
        "sys.argv",
        [
            "blint-db",
            "--db-file",
            str(db_file),
            "ingest",
            "--metadata-file",
            str(sample_metadata_file),
            "--project-name",
            "demo-cli",
            "--project-purl",
            "pkg:generic/demo-cli@1.0.0",
            "--ecosystem",
            "manual",
            "--build-system",
            "manual",
        ],
    )

    main()

    captured = capsys.readouterr()
    assert "Ingested binary_id=" in captured.out
    assert "Compacted database" in captured.out
    project_rows = execute_statement(
        "SELECT name, purl FROM Projects",
        db_file=str(db_file),
    )
    assert project_rows[0]["name"] == "demo-cli"
    assert project_rows[0]["purl"] == "pkg:generic/demo-cli@1.0.0"
    binary_rows = execute_statement(
        "SELECT name FROM Binaries",
        db_file=str(db_file),
    )
    assert binary_rows[0]["name"] == "libdemo.so"


def test_main_build_meson_writes_run_metadata_file(tmp_path, monkeypatch, capsys):
    db_file = tmp_path / "build.db"
    metadata_file = tmp_path / "build-run.json"
    monkeypatch.setattr(
        "blint_db.cli.meson_add_blint_bom_process",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "blint-db",
            "--db-file",
            str(db_file),
            "--run-metadata-file",
            str(metadata_file),
            "build-meson",
            "-s",
            "zlib",
        ],
    )

    main()

    captured = capsys.readouterr()
    assert "Compacted database" in captured.out
    assert "Wrote build metadata to" in captured.out
    assert metadata_file.exists()


def test_main_build_meson_run_metadata_includes_project_outcomes(
    tmp_path, monkeypatch, capsys
):
    db_file = tmp_path / "build.db"
    metadata_file = tmp_path / "build-run.json"
    monkeypatch.setattr(
        "blint_db.cli.meson_add_blint_bom_process",
        lambda **kwargs: [
            {
                "selector": "zlib",
                "project_name": "zlib",
                "ecosystem": "wrapdb",
                "build_system": "meson",
                "status": "build_failed",
                "artifact_count": 0,
                "failure": {"stage": "build", "message": "compile failed"},
            }
        ],
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "blint-db",
            "--db-file",
            str(db_file),
            "--run-metadata-file",
            str(metadata_file),
            "build-meson",
            "-s",
            "zlib",
        ],
    )

    main()

    captured = capsys.readouterr()
    assert "Wrote build metadata to" in captured.out
    payload = json.loads(metadata_file.read_text(encoding="utf-8"))
    assert payload["projects"]["attempted_count"] == 1
    assert payload["projects"]["failure_count"] == 1
    assert payload["projects"]["build_failures"][0]["selector"] == "zlib"


def test_main_build_cargo_writes_run_metadata_file(tmp_path, monkeypatch, capsys):
    db_file = tmp_path / "build-cargo.db"
    metadata_file = tmp_path / "build-cargo-run.json"
    monkeypatch.setattr(
        "blint_db.cli.cargo_add_blint_bom_process",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "blint-db",
            "--db-file",
            str(db_file),
            "--run-metadata-file",
            str(metadata_file),
            "build-cargo",
            "-s",
            "choose@1.3.7",
        ],
    )

    main()

    captured = capsys.readouterr()
    assert "Compacted database" in captured.out
    assert "Wrote build metadata to" in captured.out
    assert metadata_file.exists()


def test_main_build_conan_writes_run_metadata_file(tmp_path, monkeypatch, capsys):
    db_file = tmp_path / "build-conan.db"
    metadata_file = tmp_path / "build-conan-run.json"
    monkeypatch.setattr(
        "blint_db.cli.conan_add_blint_bom_process",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "blint-db",
            "--db-file",
            str(db_file),
            "--run-metadata-file",
            str(metadata_file),
            "build-conan",
            "-s",
            "fmt/11.2.0#shared-release",
        ],
    )

    main()

    captured = capsys.readouterr()
    assert "Compacted database" in captured.out
    assert "Wrote build metadata to" in captured.out
    assert metadata_file.exists()
