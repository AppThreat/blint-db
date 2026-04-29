import json

import pytest

from blint_db.handlers.language_handlers import cargo_handler
from blint_db.projects_compiler import cargo as cargo_compiler


def test_load_curated_cargo_projects_parses_csv_fields(tmp_path):
    csv_path = tmp_path / "cargo-crates.csv"
    csv_path.write_text(
        "crate,version,feature_profile,profile,default_features,features,bins,package,target\n"
        "hexyl,0.17.0,clipboard,release,false,clipboard;terminal,hexyl,hexyl,aarch64-apple-darwin\n",
        encoding="utf-8",
    )

    projects = cargo_handler.load_curated_cargo_projects(csv_path)

    assert len(projects) == 1
    project = projects[0]
    assert project.crate == "hexyl"
    assert project.version == "0.17.0"
    assert project.feature_profile == "clipboard"
    assert project.selector == "hexyl@0.17.0#clipboard"
    assert project.default_features is False
    assert project.features == ("clipboard", "terminal")
    assert project.bins == ("hexyl",)
    assert project.package == "hexyl"
    assert project.target == "aarch64-apple-darwin"


def test_default_curated_cargo_projects_file_is_packaged_and_profile_aware():
    assert cargo_handler.CARGO_CURATED_CRATES_FILE.name == "cargo-crates.csv"
    assert cargo_handler.CARGO_CURATED_CRATES_FILE.exists()

    projects = cargo_handler.load_curated_cargo_projects()
    selectors = {project.selector for project in projects}

    assert "choose@1.3.7#default" in selectors
    assert "hexyl@0.17.0#clipboard" in selectors
    assert "ripgrep@14.1.1#pcre2" in selectors


def test_load_curated_cargo_projects_keeps_legacy_csv_compatibility(tmp_path):
    csv_path = tmp_path / "cargo-crates.csv"
    csv_path.write_text(
        "crate,version,profile,default_features,features,bins,package,target\n"
        "choose,1.3.7,release,true,,choose,choose,\n",
        encoding="utf-8",
    )

    projects = cargo_handler.load_curated_cargo_projects(csv_path)

    assert len(projects) == 1
    assert projects[0].selector == "choose@1.3.7"
    assert projects[0].feature_profile is None


def test_resolve_cargo_project_spec_supports_curated_name_and_explicit_version():
    curated = [cargo_handler.CargoProjectSpec(crate="choose", version="1.3.7")]

    curated_match = cargo_handler.resolve_cargo_project_spec(
        "choose",
        curated_projects=curated,
    )
    explicit_match = cargo_handler.resolve_cargo_project_spec(
        "hexyl@0.17.0",
        curated_projects=curated,
    )

    assert curated_match.selector == "choose@1.3.7"
    assert explicit_match.selector == "hexyl@0.17.0"
    assert explicit_match.source == "manual"


def test_resolve_cargo_project_spec_supports_profile_qualified_selectors():
    curated = [
        cargo_handler.CargoProjectSpec(
            crate="hexyl",
            version="0.17.0",
            feature_profile="default",
        ),
        cargo_handler.CargoProjectSpec(
            crate="hexyl",
            version="0.17.0",
            feature_profile="clipboard",
        ),
    ]

    curated_match = cargo_handler.resolve_cargo_project_spec(
        "hexyl@0.17.0#clipboard",
        curated_projects=curated,
    )
    bare_profile_match = cargo_handler.resolve_cargo_project_spec(
        "hexyl#default",
        curated_projects=curated,
    )

    assert curated_match.selector == "hexyl@0.17.0#clipboard"
    assert bare_profile_match.selector == "hexyl@0.17.0#default"


def test_resolve_cargo_project_spec_rejects_ambiguous_crate_version_without_profile():
    curated = [
        cargo_handler.CargoProjectSpec(
            crate="hexyl",
            version="0.17.0",
            feature_profile="default",
        ),
        cargo_handler.CargoProjectSpec(
            crate="hexyl",
            version="0.17.0",
            feature_profile="clipboard",
        ),
    ]

    with pytest.raises(ValueError, match="ambiguous"):
        cargo_handler.resolve_cargo_project_spec(
            "hexyl@0.17.0",
            curated_projects=curated,
        )


def test_resolve_cargo_project_spec_rejects_unknown_bare_crate():
    with pytest.raises(ValueError, match="Use crate@version"):
        cargo_handler.resolve_cargo_project_spec("missing-crate", curated_projects=[])


def test_artifacts_from_cargo_messages_filters_non_root_and_intermediate_outputs(
    tmp_path,
):
    release_dir = tmp_path / "target" / "release"
    deps_dir = release_dir / "deps"
    release_dir.mkdir(parents=True)
    deps_dir.mkdir(parents=True)

    executable = release_dir / "choose"
    static_lib = release_dir / "libchoose.a"
    dep_rlib = deps_dir / "libdep.rlib"
    executable.write_bytes(b"\x7fELF\x00choose")
    static_lib.write_bytes(b"!<arch>\n")
    dep_rlib.write_bytes(b"rlib")

    payload = "\n".join(
        [
            json.dumps(
                {
                    "reason": "compiler-artifact",
                    "package_id": "choose 1.3.7 (path+file:///tmp)",
                    "filenames": [str(static_lib), str(dep_rlib)],
                    "executable": str(executable),
                }
            ),
            json.dumps(
                {
                    "reason": "compiler-artifact",
                    "package_id": "dependency 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
                    "filenames": [str(dep_rlib)],
                }
            ),
        ]
    )

    artifacts = cargo_handler.artifacts_from_cargo_messages(
        payload,
        root_package_id="choose 1.3.7 (path+file:///tmp)",
    )

    assert artifacts == [str(executable), str(static_lib)]


def test_find_cargo_artifacts_skips_intermediate_directories(tmp_path):
    target_dir = tmp_path / "target"
    release_dir = target_dir / "release"
    deps_dir = release_dir / "deps"
    examples_dir = release_dir / "examples"
    release_dir.mkdir(parents=True)
    deps_dir.mkdir(parents=True)
    examples_dir.mkdir(parents=True)

    binary_path = release_dir / "b3sum"
    dylib_path = release_dir / "libb3sum.dylib"
    dep_path = deps_dir / "libignored.rlib"
    example_path = examples_dir / "example"
    binary_path.write_bytes(b"\x7fELF\x00b3sum")
    dylib_path.write_bytes(b"binary")
    dep_path.write_bytes(b"binary")
    example_path.write_bytes(b"\x7fELF\x00example")

    artifacts = cargo_handler.find_cargo_artifacts(target_dir, profile="release")

    assert artifacts == [str(binary_path), str(dylib_path)]


def test_cargo_project_root_is_unique_per_feature_profile(tmp_path, monkeypatch):
    monkeypatch.setattr(cargo_handler, "BLINT_DB_BOOTSTRAP_PATH", tmp_path)
    default_spec = cargo_handler.CargoProjectSpec(
        crate="ripgrep",
        version="14.1.1",
        feature_profile="default",
    )
    pcre2_spec = cargo_handler.CargoProjectSpec(
        crate="ripgrep",
        version="14.1.1",
        feature_profile="pcre2",
    )

    assert cargo_handler.cargo_project_root(
        default_spec
    ) != cargo_handler.cargo_project_root(pcre2_spec)


def test_add_project_cargo_db_ingests_artifacts(monkeypatch, tmp_path):
    artifact_path = tmp_path / "target" / "release" / "choose"
    artifact_path.parent.mkdir(parents=True)
    artifact_path.write_bytes(b"\x7fELF\x00choose")
    spec = cargo_handler.CargoProjectSpec(crate="choose", version="1.3.7")
    captured = []

    monkeypatch.setattr(
        cargo_compiler,
        "build_cargo_project",
        lambda project_spec: cargo_handler.CargoBuildResult(
            spec=project_spec,
            project_purl="pkg:cargo/choose@1.3.7",
            project_metadata={"description": "demo"},
            build_metadata={"crate": "choose", "version": "1.3.7"},
            artifacts=[str(artifact_path)],
            source_root=tmp_path / "source",
            target_dir=tmp_path / "target",
            target_triplet="aarch64-apple-darwin",
            target_os="osx",
            target_arch="arm64",
            build_mode="release",
            optimization="release",
        ),
    )
    monkeypatch.setattr(
        cargo_compiler,
        "ingest_binary_file",
        lambda binary_file_path, **kwargs: captured.append((binary_file_path, kwargs))
        or {"binary_id": 1, "build_id": 2, "project_id": 3},
    )

    artifacts = cargo_compiler.add_project_cargo_db(spec, db_file="demo.db")

    assert artifacts == [str(artifact_path)]
    assert captured[0][0] == str(artifact_path)
    assert captured[0][1]["project_purl"] == "pkg:cargo/choose@1.3.7"
    assert captured[0][1]["ecosystem"] == "cargo"
    assert captured[0][1]["build_system"] == "cargo"
    assert captured[0][1]["target_triplet"] == "aarch64-apple-darwin"
    assert captured[0][1]["relative_to"] == tmp_path / "target"
