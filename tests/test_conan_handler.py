from pathlib import Path

import pytest

from blint_db.handlers.language_handlers import conan_handler
from blint_db.projects_compiler import conan as conan_compiler


def test_load_curated_conan_projects_parses_csv_fields(tmp_path):
    csv_path = tmp_path / "conan-center-packages.csv"
    csv_path.write_text(
        "reference,configuration,settings,options,conf,package_type,shared,build_type,target_os,target_arch,artifact_roots,notes\n"
        "fmt/11.2.0,shared-release,compiler.cppstd=20;compiler.runtime=dynamic,*:shared=True,tools.build:jobs=8,library,true,Release,Macos,x86_64,lib;bin,fmt shared build\n",
        encoding="utf-8",
    )

    projects = conan_handler.load_curated_conan_projects(csv_path)

    assert len(projects) == 1
    project = projects[0]
    assert project.reference == "fmt/11.2.0"
    assert project.selector == "fmt/11.2.0#shared-release"
    assert project.settings == (
        ("compiler.cppstd", "20"),
        ("compiler.runtime", "dynamic"),
    )
    assert project.options == (("*:shared", "True"),)
    assert project.conf == (("tools.build:jobs", "8"),)
    assert project.package_type == "library"
    assert project.shared is True
    assert project.build_type == "Release"
    assert project.target_os == "Macos"
    assert project.target_arch == "x86_64"
    assert project.artifact_roots == ("lib", "bin")


def test_default_curated_conan_projects_file_is_packaged_and_non_empty():
    assert conan_handler.CONAN_CURATED_PACKAGES_FILE.name == "conan-center-packages.csv"
    assert conan_handler.CONAN_CURATED_PACKAGES_FILE.exists()

    projects = conan_handler.load_curated_conan_projects()
    selectors = {project.selector for project in projects}

    assert "zlib/1.3.1#shared-release" in selectors
    assert "fmt/11.2.0#static-debug" in selectors
    assert "poco/1.14.2#shared-release" in selectors


def test_resolve_conan_project_spec_supports_exact_and_named_selectors():
    curated = [
        conan_handler.ConanProjectSpec(
            reference="fmt/11.2.0",
            configuration="shared-release",
        ),
        conan_handler.ConanProjectSpec(
            reference="fmt/11.2.0",
            configuration="static-debug",
        ),
    ]

    exact_match = conan_handler.resolve_conan_project_spec(
        "fmt/11.2.0#shared-release",
        curated_projects=curated,
    )
    named_match = conan_handler.resolve_conan_project_spec(
        "fmt#static-debug",
        curated_projects=curated,
    )

    assert exact_match.selector == "fmt/11.2.0#shared-release"
    assert named_match.selector == "fmt/11.2.0#static-debug"


def test_resolve_conan_project_spec_rejects_ambiguous_reference_without_configuration():
    curated = [
        conan_handler.ConanProjectSpec(
            reference="fmt/11.2.0",
            configuration="shared-release",
        ),
        conan_handler.ConanProjectSpec(
            reference="fmt/11.2.0",
            configuration="static-debug",
        ),
    ]

    with pytest.raises(ValueError, match="ambiguous"):
        conan_handler.resolve_conan_project_spec(
            "fmt/11.2.0",
            curated_projects=curated,
        )


@pytest.mark.parametrize(
    ("reference", "expected"),
    [
        (
            "poco/1.14.2@appthreat/stable",
            {
                "name": "poco",
                "version": "1.14.2",
                "user": "appthreat",
                "channel": "stable",
            },
        ),
        (
            "fmt/11.2.0",
            {
                "name": "fmt",
                "version": "11.2.0",
                "user": None,
                "channel": None,
            },
        ),
    ],
)
def test_parse_conan_reference(reference, expected):
    assert conan_handler.parse_conan_reference(reference) == expected


def test_conan_graph_info_command_uses_profiles_and_context_flags(monkeypatch):
    monkeypatch.setattr(conan_handler, "CONAN_EXECUTABLE", "conan")
    monkeypatch.setattr(conan_handler, "CONAN_REMOTE", "conancenter")
    monkeypatch.setattr(conan_handler, "CONAN_DEFAULT_HOST_PROFILE", "default")
    monkeypatch.setattr(conan_handler, "CONAN_DEFAULT_BUILD_PROFILE", "build")
    monkeypatch.setattr(
        conan_handler, "CONAN_EXTRA_GRAPH_ARGS", ("--lockfile-partial",)
    )
    spec = conan_handler.ConanProjectSpec(
        reference="fmt/11.2.0",
        configuration="shared-release",
        settings=(("compiler.cppstd", "20"),),
        options=(("*:shared", "True"),),
        conf=(("tools.build:jobs", "8"),),
        target_os="Macos",
        target_arch="x86_64",
    )

    command = conan_handler.conan_graph_info_command(spec)

    assert command[:3] == ["conan", "graph", "info"]
    assert "--format=json" in command
    assert "--output-folder" not in command
    assert command[command.index("--remote") + 1] == "conancenter"
    assert command[command.index("-pr:h") + 1] == "default"
    assert command[command.index("-pr:b") + 1] == "build"
    assert "compiler.cppstd=20" in command
    assert "os=Macos" in command
    assert "arch=x86_64" in command
    assert "*:shared=True" in command
    assert "tools.build:jobs=8" in command
    assert command[-1] == "--lockfile-partial"


def test_conan_install_command_uses_deployer_and_build_missing(monkeypatch):
    monkeypatch.setattr(conan_handler, "CONAN_EXECUTABLE", "conan")
    monkeypatch.setattr(conan_handler, "CONAN_DEFAULT_DEPLOYER", "full_deploy")
    monkeypatch.setattr(conan_handler, "CONAN_EXTRA_INSTALL_ARGS", ("--update",))
    spec = conan_handler.ConanProjectSpec(reference="zlib/1.3.1", shared=True)

    command = conan_handler.conan_install_command(
        spec,
        output_folder="/tmp/conan-install",
        deploy_root="/tmp/conan-deploy",
    )

    assert command[:2] == ["conan", "install"]
    assert "--build=missing" in command
    assert command[command.index("--output-folder") + 1] == "/tmp/conan-install"
    assert command[command.index("--deployer-folder") + 1] == "/tmp/conan-deploy"
    assert command[command.index("--deployer") + 1] == "full_deploy"
    assert command[-1] == "--update"


def test_find_conan_artifacts_filters_non_binary_content(tmp_path, monkeypatch):
    deploy_root = tmp_path / "deploy"
    (deploy_root / "pkg" / "lib").mkdir(parents=True)
    (deploy_root / "pkg" / "bin").mkdir(parents=True)
    (deploy_root / "pkg" / "include").mkdir(parents=True)
    (deploy_root / "pkg" / "share" / "doc").mkdir(parents=True)

    library_file = deploy_root / "pkg" / "lib" / "libfmt.dylib"
    executable_file = deploy_root / "pkg" / "bin" / "fmt-tool"
    header_file = deploy_root / "pkg" / "include" / "fmt.h"
    readme_file = deploy_root / "pkg" / "share" / "doc" / "README.md"
    library_file.write_bytes(b"binary")
    executable_file.write_bytes(b"binary")
    header_file.write_text("#pragma once", encoding="utf-8")
    readme_file.write_text("docs", encoding="utf-8")

    monkeypatch.setattr(
        conan_handler,
        "is_exe",
        lambda path: str(path).endswith("fmt-tool"),
    )

    artifacts = conan_handler.find_conan_artifacts(deploy_root)

    assert artifacts == [str(executable_file), str(library_file)]


def test_add_project_conan_db_ingests_artifacts(monkeypatch, tmp_path):
    artifact_path = tmp_path / "deploy" / "lib" / "libfmt.dylib"
    artifact_path.parent.mkdir(parents=True)
    artifact_path.write_bytes(b"binary")
    spec = conan_handler.ConanProjectSpec(
        reference="fmt/11.2.0",
        configuration="shared-release",
    )
    captured = []

    monkeypatch.setattr(
        conan_compiler,
        "build_conan_project",
        lambda project_spec: conan_compiler.ConanBuildResult(
            spec=project_spec,
            project_purl="pkg:conan/fmt@11.2.0?configuration=shared-release",
            project_metadata={"description": "fmt"},
            build_metadata={
                "reference": "fmt/11.2.0",
                "selector": project_spec.selector,
            },
            artifacts=[str(artifact_path)],
            build_root=tmp_path,
            deploy_root=tmp_path / "deploy",
            package_roots=[tmp_path / "cache" / "fmt"],
            target_triplet="x86_64-Macos-conan",
            target_os="Macos",
            target_arch="x86_64",
            build_mode="Release",
            optimization="release",
        ),
    )
    monkeypatch.setattr(
        conan_compiler,
        "ingest_binary_file",
        lambda binary_file_path, **kwargs: captured.append((binary_file_path, kwargs))
        or {"binary_id": 1, "build_id": 2, "project_id": 3},
    )

    artifacts = conan_compiler.add_project_conan_db(spec, db_file="demo.db")

    assert artifacts == [str(artifact_path)]
    assert captured[0][0] == str(artifact_path)
    assert captured[0][1]["project_purl"].startswith("pkg:conan/fmt@11.2.0")
    assert captured[0][1]["ecosystem"] == "conan"
    assert captured[0][1]["build_system"] == "conan"
    assert captured[0][1]["relative_to"] == tmp_path / "deploy"
