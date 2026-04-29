# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import logging
import os
import platform
import shutil
from pathlib import Path

from blint_db.utils.json import split_shell_args

logger = logging.getLogger(__name__)
logging.basicConfig(format="%(message)s", level=logging.INFO)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in ("1", "true", "yes", "on")


DELIMETER_BOM = "~~"
DEBUG_MODE = True if os.getenv("BLINT_DB_DEBUG_MODE", "0") == "1" else False

BLINT_DB_BOOTSTRAP_PATH = Path(
    os.getenv("BLINT_DB_BOOTSTRAP_PATH", str(Path.cwd() / "temp"))
)
WRAPDB_LOCATION = BLINT_DB_BOOTSTRAP_PATH / "wrapdb"
VCPKG_LOCATION = BLINT_DB_BOOTSTRAP_PATH / "vcpkg"
DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = Path(__file__).resolve().parent

WRAPDB_URL = "https://github.com/mesonbuild/wrapdb.git"
VCPKG_URL = "https://github.com/microsoft/vcpkg.git"
HOMEBREW_CORE_TAP = os.getenv("BLINT_DB_HOMEBREW_CORE_TAP", "homebrew/core")

WRAPDB_COMMIT_HASH = "e74bfb6078dd4805d346d1fc38d0f6ad198443ad"
VCPKG_COMMIT_HASH = "63bb8e44c140791580201d29c0c16985a88969cf"

BOM_LOCATION = BLINT_DB_BOOTSTRAP_PATH / "BOM"
BLINT_DB_FILE = os.getenv("BLINT_DB_FILE", "blint-v2.db")
BLINT_DB_SCHEMA_VERSION = 2
BLINT_DB_SCHEMA_FAMILY = "blint-db"
CWD = Path(os.getcwd())

SQLITE_TIMEOUT = 20.0
BUILD_JOBS = max(1, int(os.getenv("BLINT_DB_BUILD_JOBS", os.cpu_count() or 1)))
MESON_BUILD_TYPE = os.getenv("BLINT_DB_MESON_BUILDTYPE", "debug")
MESON_DEFAULT_LIBRARY = os.getenv("BLINT_DB_MESON_DEFAULT_LIBRARY", "shared")
MESON_STRIP = _env_bool("BLINT_DB_MESON_STRIP", True)
MESON_WARN_LEVEL = os.getenv("BLINT_DB_MESON_WARN_LEVEL", "0")
MESON_EXTRA_SETUP_ARGS = split_shell_args(
    os.getenv("BLINT_DB_MESON_EXTRA_SETUP_ARGS", "")
)
MESON_EXTRA_COMPILE_ARGS = split_shell_args(
    os.getenv("BLINT_DB_MESON_EXTRA_COMPILE_ARGS", "")
)

HOMEBREW_EXECUTABLE = os.getenv(
    "BLINT_DB_HOMEBREW_EXECUTABLE",
    shutil.which("brew") or "/opt/homebrew/bin/brew",
)
HOMEBREW_BUILD_FROM_SOURCE = _env_bool("BLINT_DB_HOMEBREW_BUILD_FROM_SOURCE", False)
HOMEBREW_REINSTALL_EXISTING = _env_bool("BLINT_DB_HOMEBREW_REINSTALL_EXISTING", False)
HOMEBREW_NO_AUTO_UPDATE = _env_bool("HOMEBREW_NO_AUTO_UPDATE", True)
HOMEBREW_NO_INSTALL_CLEANUP = _env_bool("HOMEBREW_NO_INSTALL_CLEANUP", True)
HOMEBREW_NO_ANALYTICS = _env_bool("HOMEBREW_NO_ANALYTICS", True)
HOMEBREW_EXTRA_INSTALL_ARGS = split_shell_args(
    os.getenv("BLINT_DB_HOMEBREW_INSTALL_ARGS", "")
)


def _default_curated_input_file(filename: str) -> Path:
    if inputs_dir := os.getenv("BLINT_DB_INPUTS_DIR"):
        return Path(inputs_dir) / filename
    package_candidate = PACKAGE_ROOT / "inputs" / filename
    if package_candidate.exists():
        return package_candidate
    return DEFAULT_REPO_ROOT / "inputs" / filename


HOMEBREW_CURATED_FORMULAS_FILE = Path(
    os.getenv(
        "BLINT_DB_HOMEBREW_FORMULAS_FILE",
        str(_default_curated_input_file("homebrew-formulas.csv")),
    )
)

CARGO_EXECUTABLE = os.getenv(
    "BLINT_DB_CARGO_EXECUTABLE", shutil.which("cargo") or "cargo"
)
CARGO_REGISTRY_API = os.getenv("BLINT_DB_CARGO_REGISTRY_API", "https://crates.io")
CARGO_HTTP_TIMEOUT = max(5, int(os.getenv("BLINT_DB_CARGO_HTTP_TIMEOUT", "60")))
CARGO_CURATED_CRATES_FILE = Path(
    os.getenv(
        "BLINT_DB_CARGO_CRATES_FILE",
        str(_default_curated_input_file("cargo-crates.csv")),
    )
)
CARGO_DEFAULT_PROFILE = os.getenv("BLINT_DB_CARGO_PROFILE", "release")
CARGO_DEFAULT_TARGET = os.getenv("BLINT_DB_CARGO_TARGET") or None
CARGO_FEW_PACKAGES = max(1, int(os.getenv("BLINT_DB_CARGO_FEW_PACKAGES", "2")))
CARGO_EXTRA_FETCH_ARGS = split_shell_args(os.getenv("BLINT_DB_CARGO_FETCH_ARGS", ""))
CARGO_EXTRA_BUILD_ARGS = split_shell_args(os.getenv("BLINT_DB_CARGO_BUILD_ARGS", ""))

CONAN_EXECUTABLE = os.getenv(
    "BLINT_DB_CONAN_EXECUTABLE", shutil.which("conan") or "conan"
)
CONAN_REMOTE = os.getenv("BLINT_DB_CONAN_REMOTE", "conancenter")
CONAN_REMOTE_URL = os.getenv("BLINT_DB_CONAN_REMOTE_URL") or None
CONAN_CURATED_PACKAGES_FILE = Path(
    os.getenv(
        "BLINT_DB_CONAN_PACKAGES_FILE",
        str(_default_curated_input_file("conan-center-packages.csv")),
    )
)
CONAN_DEFAULT_BUILD_TYPE = os.getenv("BLINT_DB_CONAN_BUILD_TYPE", "Release")
CONAN_DEFAULT_HOST_PROFILE = os.getenv("BLINT_DB_CONAN_HOST_PROFILE") or None
CONAN_DEFAULT_BUILD_PROFILE = os.getenv("BLINT_DB_CONAN_BUILD_PROFILE") or None
CONAN_DEFAULT_DEPLOYER = os.getenv("BLINT_DB_CONAN_DEPLOYER", "full_deploy")
CONAN_FEW_PACKAGES = max(1, int(os.getenv("BLINT_DB_CONAN_FEW_PACKAGES", "3")))
CONAN_EXTRA_GRAPH_ARGS = split_shell_args(os.getenv("BLINT_DB_CONAN_GRAPH_ARGS", ""))
CONAN_EXTRA_INSTALL_ARGS = split_shell_args(
    os.getenv("BLINT_DB_CONAN_INSTALL_ARGS", "")
)

COMMON_CONNECTION = None
ARCH = platform.machine()
SYSTEM = platform.system().lower()
if ARCH == "x86_64":
    ARCH = "x64"
if ARCH == "aarch64":
    ARCH = "arm64"
if SYSTEM == "darwin":
    SYSTEM = "osx"
VCPKG_ARCH_OS = f"{ARCH}-{SYSTEM}"
VCPKG_DEFAULT_TRIPLET = os.getenv("BLINT_DB_VCPKG_TRIPLET", VCPKG_ARCH_OS)
VCPKG_HOST_TRIPLET = os.getenv("BLINT_DB_VCPKG_HOST_TRIPLET")
VCPKG_KEEP_GOING = _env_bool("BLINT_DB_VCPKG_KEEP_GOING", True)
VCPKG_CLEAN_AFTER_BUILD = _env_bool("BLINT_DB_VCPKG_CLEAN_AFTER_BUILD", True)
VCPKG_DISABLE_METRICS = _env_bool("VCPKG_DISABLE_METRICS", True)
VCPKG_FEATURE_FLAGS = tuple(
    part.strip()
    for part in os.getenv("BLINT_DB_VCPKG_FEATURE_FLAGS", "").split(",")
    if part.strip()
)
VCPKG_EXTRA_INSTALL_ARGS = split_shell_args(
    os.getenv("BLINT_DB_VCPKG_INSTALL_ARGS", "")
)

for log_name, log_obj in logging.Logger.manager.loggerDict.items():
    if log_name != __name__:
        log_obj.disabled = True

IGNORE_DIRECTORIES = [
    ".git",
    ".svn",
    ".mvn",
    ".idea",
    "dist",
    "bin",
    "obj",
    "backup",
    "docs",
    "tests",
    "test",
    "testsuitetmp",
    "report",
    "reports",
    "node_modules",
    ".terraform",
    ".serverless",
    "venv",
    "examples",
    "tutorials",
    "samples",
    "migrations",
    "db_migrations",
    "unittests",
    "unittests_legacy",
    "stubs",
    "mock",
    "mocks",
]
