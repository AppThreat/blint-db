# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from blint_db import (
    ARCH,
    BLINT_DB_BOOTSTRAP_PATH,
    CONAN_CURATED_PACKAGES_FILE,
    CONAN_DEFAULT_BUILD_PROFILE,
    CONAN_DEFAULT_BUILD_TYPE,
    CONAN_DEFAULT_DEPLOYER,
    CONAN_DEFAULT_HOST_PROFILE,
    CONAN_EXECUTABLE,
    CONAN_EXTRA_GRAPH_ARGS,
    CONAN_EXTRA_INSTALL_ARGS,
    CONAN_REMOTE,
    CONAN_REMOTE_URL,
    DEBUG_MODE,
    SYSTEM,
    logger,
)
from blint_db.handlers.language_handlers import BaseHandler
from blint_db.utils import is_exe

_CONAN_DEFAULT_ARTIFACT_ROOTS = ("bin", "lib", "lib64", "Frameworks")
_CONAN_SKIP_DIRS = {
    ".git",
    ".conan",
    "build",
    "builddirs",
    "cmake",
    "doc",
    "docs",
    "examples",
    "include",
    "licenses",
    "man",
    "pkgconfig",
    "res",
    "resources",
    "share",
    "test",
    "tests",
}
_CONAN_LIBRARY_SUFFIXES = {".a", ".lib", ".so", ".dylib", ".dll", ".wasm", ".exe"}


@dataclass(frozen=True, slots=True)
class ConanProjectSpec:
    reference: str
    configuration: str | None = None
    settings: tuple[tuple[str, str], ...] = ()
    options: tuple[tuple[str, str], ...] = ()
    conf: tuple[tuple[str, str], ...] = ()
    package_type: str | None = None
    shared: bool | None = None
    build_type: str = CONAN_DEFAULT_BUILD_TYPE
    target_os: str | None = None
    target_arch: str | None = None
    artifact_roots: tuple[str, ...] = _CONAN_DEFAULT_ARTIFACT_ROOTS
    notes: str | None = None
    source: str = "curated"

    @property
    def selector(self) -> str:
        if self.configuration:
            return f"{self.reference}#{self.configuration}"
        return self.reference

    @property
    def name(self) -> str:
        return parse_conan_reference(self.reference)["name"]

    @property
    def version(self) -> str | None:
        return parse_conan_reference(self.reference).get("version")


def _split_csv_list(raw_value: str | None) -> tuple[str, ...]:
    if not raw_value:
        return ()
    return tuple(part.strip() for part in re.split(r"[;,]", raw_value) if part.strip())


def _parse_bool(raw_value: str | None, *, default: bool | None = None) -> bool | None:
    if raw_value is None or raw_value == "":
        return default
    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _parse_kv_pairs(raw_value: str | None) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for part in _split_csv_list(raw_value):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key and value:
            pairs.append((key, value))
    return tuple(pairs)


def _pairs_to_dict(pairs: tuple[tuple[str, str], ...]) -> dict[str, str]:
    return {key: value for key, value in pairs}


def _slugify_selector(selector: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", selector)


def parse_conan_reference(reference: str) -> dict[str, str | None]:
    reference_without_revisions = reference.split(":", 1)[0].split("#", 1)[0]
    name_version, has_user_channel, user_channel = (
        reference_without_revisions.partition("@")
    )
    name, has_version, version = name_version.partition("/")
    user = None
    channel = None
    if has_user_channel and user_channel:
        user, _, channel = user_channel.partition("/")
    return {
        "name": name.strip(),
        "version": version.strip() if has_version else None,
        "user": user.strip() if user else None,
        "channel": channel.strip() if channel else None,
    }


def _parse_conan_selector(selector: str) -> tuple[str, str | None]:
    reference, has_configuration, configuration = selector.strip().partition("#")
    return reference.strip(), configuration.strip() if has_configuration else None


def _conan_os_name(raw_os: str | None) -> str | None:
    normalized = (raw_os or SYSTEM).strip().lower()
    mapping = {
        "darwin": "Macos",
        "macos": "Macos",
        "osx": "Macos",
        "linux": "Linux",
        "windows": "Windows",
        "android": "Android",
        "ios": "iOS",
        "wasm": "Emscripten",
    }
    return mapping.get(normalized, raw_os)


def _conan_arch_name(raw_arch: str | None) -> str | None:
    normalized = (raw_arch or ARCH).strip().lower()
    mapping = {
        "x64": "x86_64",
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "arm64": "armv8",
        "aarch64": "armv8",
        "armv8": "armv8",
        "x86": "x86",
    }
    return mapping.get(normalized, raw_arch)


def _effective_settings(spec: ConanProjectSpec) -> tuple[tuple[str, str], ...]:
    settings = dict(spec.settings)
    settings.setdefault("build_type", spec.build_type or CONAN_DEFAULT_BUILD_TYPE)
    if os_name := _conan_os_name(spec.target_os):
        settings.setdefault("os", os_name)
    if arch_name := _conan_arch_name(spec.target_arch):
        settings.setdefault("arch", arch_name)
    return tuple((key, settings[key]) for key in sorted(settings))


def _effective_options(spec: ConanProjectSpec) -> tuple[tuple[str, str], ...]:
    options = dict(spec.options)
    if spec.shared is not None and not any(key.endswith("shared") for key in options):
        options["*:shared"] = "True" if spec.shared else "False"
    return tuple((key, options[key]) for key in sorted(options))


def _json_from_output(output: str | None) -> dict[str, Any]:
    if not output:
        return {}
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {}


class ConanHandler(BaseHandler):
    strip = False

    def build(self, project_name):
        from blint_db.projects_compiler.conan import build_conan_project

        return build_conan_project(resolve_conan_project_spec(project_name))

    def find_executables(self, project_name):
        from blint_db.projects_compiler.conan import build_conan_project

        return build_conan_project(resolve_conan_project_spec(project_name)).artifacts

    def delete_project_files(self, project_name):
        shutil.rmtree(
            conan_project_root(resolve_conan_project_spec(project_name)),
            ignore_errors=True,
        )

    def get_project_list(self):
        return [project.selector for project in load_curated_conan_projects()]


def load_curated_conan_projects(
    file_path: str | os.PathLike | None = None,
) -> list[ConanProjectSpec]:
    csv_path = Path(file_path or CONAN_CURATED_PACKAGES_FILE)
    if not csv_path.exists():
        return []
    projects: list[ConanProjectSpec] = []
    with open(csv_path, "r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            reference = (row.get("reference") or "").strip()
            if not reference:
                name = (row.get("name") or "").strip()
                version = (row.get("version") or "").strip()
                if name and version:
                    reference = f"{name}/{version}"
            if not reference:
                continue
            projects.append(
                ConanProjectSpec(
                    reference=reference,
                    configuration=(row.get("configuration") or "").strip() or None,
                    settings=_parse_kv_pairs(row.get("settings")),
                    options=_parse_kv_pairs(row.get("options")),
                    conf=_parse_kv_pairs(row.get("conf")),
                    package_type=(row.get("package_type") or "").strip() or None,
                    shared=_parse_bool(row.get("shared"), default=None),
                    build_type=(
                        row.get("build_type") or CONAN_DEFAULT_BUILD_TYPE
                    ).strip()
                    or CONAN_DEFAULT_BUILD_TYPE,
                    target_os=(row.get("target_os") or "").strip() or None,
                    target_arch=(row.get("target_arch") or "").strip() or None,
                    artifact_roots=_split_csv_list(row.get("artifact_roots"))
                    or _CONAN_DEFAULT_ARTIFACT_ROOTS,
                    notes=(row.get("notes") or "").strip() or None,
                    source="curated",
                )
            )
    return projects


def resolve_conan_project_spec(
    selector: str,
    *,
    curated_projects: list[ConanProjectSpec] | None = None,
) -> ConanProjectSpec:
    normalized_selector = selector.strip()
    projects = (
        curated_projects
        if curated_projects is not None
        else load_curated_conan_projects()
    )
    for project in projects:
        if project.selector == normalized_selector:
            return project
    reference, configuration = _parse_conan_selector(normalized_selector)
    matches = [project for project in projects if project.reference == reference]
    if configuration is not None:
        matches = [
            project for project in matches if project.configuration == configuration
        ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise ValueError(
            f"Conan selector '{selector}' is ambiguous. Use one of: {', '.join(project.selector for project in matches)}"
        )
    reference_parts = parse_conan_reference(reference)
    name_matches = [
        project for project in projects if project.name == reference_parts["name"]
    ]
    if configuration is not None:
        name_matches = [
            project
            for project in name_matches
            if project.configuration == configuration
        ]
    if len(name_matches) == 1 and "/" not in reference:
        return name_matches[0]
    if len(name_matches) > 1 and "/" not in reference:
        raise ValueError(
            f"Conan package selector '{selector}' is ambiguous. Use one of: {', '.join(project.selector for project in name_matches)}"
        )
    if "/" not in reference:
        raise ValueError(
            f"Unknown Conan package '{selector}'. Use name/version or one of the curated entries."
        )
    return ConanProjectSpec(
        reference=reference, configuration=configuration, source="manual"
    )


def conan_project_root(spec: ConanProjectSpec) -> Path:
    return BLINT_DB_BOOTSTRAP_PATH / "conan" / _slugify_selector(spec.selector)


def conan_environment(build_root: str | os.PathLike) -> dict[str, str]:
    root = Path(build_root)
    env = os.environ.copy()
    env["CONAN_HOME"] = str(root / "conan-home")
    env.setdefault("CONAN_NON_INTERACTIVE", "1")
    env.setdefault("CLICOLOR", "0")
    return env


def _run_conan_command(
    command: list[str],
    *,
    cwd: str | os.PathLike,
    env: dict[str, str],
    capture_output: bool = True,
    project_name: str = "conan",
) -> subprocess.CompletedProcess:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=capture_output or DEBUG_MODE,
        check=False,
        encoding="utf-8",
    )
    if DEBUG_MODE and result.stderr:
        logger.debug("%s: %s", project_name, result.stderr)
    return result


def _require_conan() -> None:
    executable = str(CONAN_EXECUTABLE)
    if not shutil.which(executable) and not Path(executable).exists():
        raise ModuleNotFoundError(f"Conan executable was not found: {CONAN_EXECUTABLE}")


def conan_profile_detect_command() -> list[str]:
    return [CONAN_EXECUTABLE, "profile", "detect", "--force"]


def _extend_host_context_args(
    command: list[str], flag: str, pairs: tuple[tuple[str, str], ...]
) -> None:
    for key, value in pairs:
        command.extend([flag, f"{key}={value}"])


def conan_graph_info_command(
    spec: ConanProjectSpec,
    *,
    output_folder: str | os.PathLike,
) -> list[str]:
    command = [
        CONAN_EXECUTABLE,
        "graph",
        "info",
        f"--requires={spec.reference}",
        "--format=json",
        "--output-folder",
        str(output_folder),
        "--build=missing",
    ]
    if CONAN_REMOTE:
        command.extend(["--remote", CONAN_REMOTE])
    if CONAN_DEFAULT_HOST_PROFILE:
        command.extend(["-pr:h", CONAN_DEFAULT_HOST_PROFILE])
    if CONAN_DEFAULT_BUILD_PROFILE:
        command.extend(["-pr:b", CONAN_DEFAULT_BUILD_PROFILE])
    _extend_host_context_args(command, "-s:h", _effective_settings(spec))
    _extend_host_context_args(command, "-o:h", _effective_options(spec))
    _extend_host_context_args(command, "-c:h", spec.conf)
    command.extend(CONAN_EXTRA_GRAPH_ARGS)
    return command


def conan_install_command(
    spec: ConanProjectSpec,
    *,
    output_folder: str | os.PathLike,
    deploy_root: str | os.PathLike,
) -> list[str]:
    command = [
        CONAN_EXECUTABLE,
        "install",
        f"--requires={spec.reference}",
        "--format=json",
        "--output-folder",
        str(output_folder),
        "--deployer",
        CONAN_DEFAULT_DEPLOYER,
        "--deployer-folder",
        str(deploy_root),
        "--build=missing",
    ]
    if CONAN_REMOTE:
        command.extend(["--remote", CONAN_REMOTE])
    if CONAN_DEFAULT_HOST_PROFILE:
        command.extend(["-pr:h", CONAN_DEFAULT_HOST_PROFILE])
    if CONAN_DEFAULT_BUILD_PROFILE:
        command.extend(["-pr:b", CONAN_DEFAULT_BUILD_PROFILE])
    _extend_host_context_args(command, "-s:h", _effective_settings(spec))
    _extend_host_context_args(command, "-o:h", _effective_options(spec))
    _extend_host_context_args(command, "-c:h", spec.conf)
    command.extend(CONAN_EXTRA_INSTALL_ARGS)
    return command


def ensure_conan_profiles(build_root: str | os.PathLike) -> None:
    _require_conan()
    if CONAN_DEFAULT_HOST_PROFILE and CONAN_DEFAULT_BUILD_PROFILE:
        return
    root = Path(build_root)
    root.mkdir(parents=True, exist_ok=True)
    env = conan_environment(root)
    result = _run_conan_command(
        conan_profile_detect_command(),
        cwd=root,
        env=env,
        project_name="conan-profile-detect",
    )
    if result.returncode != 0:
        raise RuntimeError("conan profile detect failed")


def conan_graph_info(
    spec: ConanProjectSpec, *, build_root: str | os.PathLike
) -> dict[str, Any]:
    ensure_conan_profiles(build_root)
    root = Path(build_root)
    env = conan_environment(root)
    result = _run_conan_command(
        conan_graph_info_command(spec, output_folder=root / "graph"),
        cwd=root,
        env=env,
        project_name=spec.selector,
    )
    if result.returncode != 0:
        raise RuntimeError(f"conan graph info failed for {spec.selector}")
    return _json_from_output(result.stdout)


def conan_install(
    spec: ConanProjectSpec, *, build_root: str | os.PathLike
) -> dict[str, Any]:
    ensure_conan_profiles(build_root)
    root = Path(build_root)
    root.mkdir(parents=True, exist_ok=True)
    deploy_root = root / "deploy"
    output_root = root / "install"
    env = conan_environment(root)
    result = _run_conan_command(
        conan_install_command(spec, output_folder=output_root, deploy_root=deploy_root),
        cwd=root,
        env=env,
        project_name=spec.selector,
    )
    if result.returncode != 0:
        raise RuntimeError(f"conan install failed for {spec.selector}")
    return _json_from_output(result.stdout)


def _graph_nodes(graph_payload: dict[str, Any]) -> list[dict[str, Any]]:
    if not graph_payload:
        return []
    graph = graph_payload.get("graph") or graph_payload
    nodes = graph.get("nodes") or []
    if isinstance(nodes, dict):
        return [node for node in nodes.values() if isinstance(node, dict)]
    if isinstance(nodes, list):
        return [node for node in nodes if isinstance(node, dict)]
    return []


def _matching_reference_nodes(
    graph_payload: dict[str, Any], spec: ConanProjectSpec
) -> list[dict[str, Any]]:
    normalized_reference = spec.reference.split("#", 1)[0]
    return [
        node
        for node in _graph_nodes(graph_payload)
        if (node.get("ref") or node.get("reference") or "").split("#", 1)[0]
        == normalized_reference
    ]


def conan_package_roots(
    graph_payload: dict[str, Any], spec: ConanProjectSpec | None = None
) -> list[Path]:
    candidate_nodes = (
        _matching_reference_nodes(graph_payload, spec)
        if spec is not None
        else _graph_nodes(graph_payload)
    )
    roots: list[Path] = []
    for node in candidate_nodes:
        for candidate in (
            node.get("package_folder"),
            (node.get("package") or {}).get("folder"),
            (node.get("folders") or {}).get("package_folder"),
        ):
            if candidate:
                path_obj = Path(candidate)
                if path_obj.exists():
                    roots.append(path_obj)
    deduped: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        resolved = str(root.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(root)
    return deduped


def conan_cache_path(build_root: str | os.PathLike) -> str | None:
    _require_conan()
    root = Path(build_root)
    env = conan_environment(root)
    result = _run_conan_command(
        [CONAN_EXECUTABLE, "cache", "path"],
        cwd=root,
        env=env,
        project_name="conan-cache-path",
    )
    if result.returncode != 0:
        return None
    return (result.stdout or "").strip() or None


def conan_remote_metadata(build_root: str | os.PathLike) -> dict[str, Any] | None:
    _require_conan()
    root = Path(build_root)
    env = conan_environment(root)
    result = _run_conan_command(
        [CONAN_EXECUTABLE, "remote", "list", "--format=json"],
        cwd=root,
        env=env,
        project_name="conan-remote-list",
    )
    payload = _json_from_output(result.stdout)
    remotes = payload.get("remotes") if isinstance(payload, dict) else None
    if remotes:
        for remote in remotes:
            if remote.get("name") == CONAN_REMOTE:
                return remote
    if CONAN_REMOTE or CONAN_REMOTE_URL:
        return {
            "name": CONAN_REMOTE,
            "url": CONAN_REMOTE_URL,
        }
    return None


def _should_skip_dir(path_obj: Path) -> bool:
    return any(part.lower() in _CONAN_SKIP_DIRS for part in path_obj.parts)


def _scan_roots(root_path: Path, artifact_roots: tuple[str, ...]) -> list[Path]:
    selected_roots = [
        path_obj
        for path_obj in root_path.rglob("*")
        if path_obj.is_dir() and path_obj.name in set(artifact_roots)
    ]
    return selected_roots or [root_path]


def _is_supported_conan_artifact(file_path: str | os.PathLike) -> bool:
    path_obj = Path(file_path)
    if not path_obj.exists() or not path_obj.is_file():
        return False
    if _should_skip_dir(path_obj.parent):
        return False
    if path_obj.suffix.lower() in _CONAN_LIBRARY_SUFFIXES:
        return True
    return is_exe(str(path_obj))


def find_conan_artifacts(
    root_path: str | os.PathLike,
    *,
    artifact_roots: tuple[str, ...] = _CONAN_DEFAULT_ARTIFACT_ROOTS,
) -> list[str]:
    base_root = Path(root_path)
    if not base_root.exists():
        return []
    artifacts: dict[str, Path] = {}
    for scan_root in _scan_roots(base_root, artifact_roots):
        for path_obj in scan_root.rglob("*"):
            if not _is_supported_conan_artifact(path_obj):
                continue
            resolved = str(path_obj.resolve())
            current = artifacts.get(resolved)
            if current is None or len(str(path_obj)) < len(str(current)):
                artifacts[resolved] = path_obj
    return sorted(str(path) for path in artifacts.values())


def find_conan_artifacts_from_roots(
    roots: list[str | os.PathLike],
    *,
    artifact_roots: tuple[str, ...] = _CONAN_DEFAULT_ARTIFACT_ROOTS,
) -> list[str]:
    artifacts: list[str] = []
    for root in roots:
        artifacts.extend(find_conan_artifacts(root, artifact_roots=artifact_roots))
    return sorted(dict.fromkeys(artifacts))
