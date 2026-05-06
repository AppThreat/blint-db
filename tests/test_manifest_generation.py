import csv
import json

from blint_db.utils import manifest_generation


def test_build_homebrew_manifest_rows_uses_metadata_and_limit():
    metadata = {
        "fmt": {"desc": "C++ formatting library", "dependencies": []},
        "ripgrep": {"desc": "Rust search tool", "build_dependencies": ["rust"]},
    }

    rows = manifest_generation.build_homebrew_manifest_rows(
        ["fmt", "ripgrep"],
        limit=1,
        metadata_loader=lambda formula_name: metadata[formula_name],
    )

    assert rows == [
        {
            "formula": "fmt",
            "language_family": "c++",
            "upstream_ecosystem": "c++",
            "reason": "top_installs_rank_1",
            "notes": "C++ formatting library",
        }
    ]


def test_build_homebrew_manifest_rows_tolerates_metadata_lookup_failures():
    rows = manifest_generation.build_homebrew_manifest_rows(
        ["hashicorp/tap/terraform"],
        limit=1,
        metadata_loader=lambda _formula_name: (_ for _ in ()).throw(
            RuntimeError("404")
        ),
    )

    assert rows == [
        {
            "formula": "hashicorp/tap/terraform",
            "language_family": "c",
            "upstream_ecosystem": "c",
            "reason": "top_installs_rank_1",
            "notes": "",
        }
    ]


def test_build_cargo_manifest_rows_can_emit_dev_profile_duplicates():
    payload = {
        "crates": [
            {"id": "bat", "max_version": "0.26.0"},
            {"id": "ripgrep", "max_version": "14.1.1"},
        ]
    }

    rows = manifest_generation.build_cargo_manifest_rows(
        payload,
        limit=2,
        include_dev_profile=True,
    )

    assert rows[0]["crate"] == "bat"
    assert rows[0]["feature_profile"] == "default"
    assert rows[1]["feature_profile"] == "debug"
    assert rows[1]["profile"] == "dev"
    assert rows[2]["crate"] == "ripgrep"


def test_build_conan_manifest_rows_emits_release_and_debug_variants():
    rows = manifest_generation.build_conan_manifest_rows(
        ["fmt/11.2.0", "zlib/1.3.1"],
        limit=2,
    )

    assert rows[0]["configuration"] == "shared-release"
    assert rows[0]["build_type"] == "Release"
    assert rows[1]["configuration"] == "static-debug"
    assert rows[1]["build_type"] == "Debug"
    assert rows[2]["reference"] == "zlib/1.3.1"


def test_generate_homebrew_manifest_writes_csv(tmp_path, monkeypatch):
    monkeypatch.setattr(
        manifest_generation,
        "fetch_homebrew_top_formulae",
        lambda limit: ["fmt", "ripgrep"][:limit],
    )
    monkeypatch.setattr(
        manifest_generation,
        "fetch_homebrew_formula_metadata",
        lambda formula_name: {"desc": f"{formula_name} desc", "dependencies": []},
    )

    output_file = tmp_path / "homebrew-formulas.csv"
    manifest_generation.generate_homebrew_manifest(limit=2, output_file=output_file)

    rows = list(csv.DictReader(output_file.open(encoding="utf-8")))
    assert [row["formula"] for row in rows] == ["fmt", "ripgrep"]


def test_fetch_homebrew_top_formulae_supports_current_items_payload(monkeypatch):
    monkeypatch.setattr(
        manifest_generation,
        "_fetch_json",
        lambda _url, timeout=60: {
            "category": "install-on-request",
            "items": [
                {"number": 1, "formula": "gh"},
                {"number": 2, "formula": "node"},
                {"number": 3, "formula": "git"},
            ],
        },
    )

    assert manifest_generation.fetch_homebrew_top_formulae(2) == ["gh", "node"]


def test_generate_cargo_manifest_writes_csv(tmp_path, monkeypatch):
    monkeypatch.setattr(
        manifest_generation,
        "fetch_cargo_crates_page",
        lambda **kwargs: {"crates": [{"id": "bat", "max_version": "0.26.0"}]},
    )

    output_file = tmp_path / "cargo-crates.csv"
    manifest_generation.generate_cargo_manifest(limit=1, output_file=output_file)

    rows = list(csv.DictReader(output_file.open(encoding="utf-8")))
    assert rows[0]["crate"] == "bat"
    assert rows[0]["version"] == "0.26.0"


def test_generate_conan_manifest_writes_csv_from_seed(tmp_path):
    output_file = tmp_path / "conan-center-packages.csv"
    manifest_generation.generate_conan_manifest(limit=1, output_file=output_file)

    rows = list(csv.DictReader(output_file.open(encoding="utf-8")))
    assert rows[0]["reference"] == "zlib/1.3.1"
    assert rows[0]["configuration"] == "shared-release"
    assert rows[1]["configuration"] == "static-debug"


def test_resolve_conan_reference_versions_uses_conan_search(monkeypatch):
    class _Completed:
        def __init__(self, stdout, returncode=0):
            self.stdout = stdout
            self.returncode = returncode

    monkeypatch.setattr(
        manifest_generation.subprocess,
        "run",
        lambda *args, **kwargs: _Completed(
            json.dumps(
                {
                    "results": [
                        {
                            "items": [
                                {"reference": "fmt/11.2.0"},
                            ]
                        }
                    ]
                }
            )
        ),
    )

    resolved = manifest_generation.resolve_conan_reference_versions(["fmt"])

    assert resolved == ["fmt/11.2.0"]
