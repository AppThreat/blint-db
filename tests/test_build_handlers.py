from pathlib import Path

from blint_db.handlers.language_handlers import meson_handler, vcpkg_handler
from blint_db.handlers.language_handlers import cargo_handler


def test_meson_setup_command_uses_configurable_defaults(monkeypatch):
    monkeypatch.setattr(meson_handler, "MESON_BUILD_TYPE", "plain")
    monkeypatch.setattr(meson_handler, "MESON_DEFAULT_LIBRARY", "static")
    monkeypatch.setattr(meson_handler, "MESON_STRIP", False)
    monkeypatch.setattr(meson_handler, "BUILD_JOBS", 7)
    monkeypatch.setattr(meson_handler, "MESON_WARN_LEVEL", "1")
    monkeypatch.setattr(meson_handler, "MESON_EXTRA_SETUP_ARGS", ("-Db_lto=true",))

    command = meson_handler.meson_setup_command("zlib")

    assert command[:3] == ["meson", "setup", str(meson_handler.build_dir_for("zlib"))]
    assert "-Dwraps=zlib" in command
    assert "-Dbuildtype=plain" in command
    assert "-Ddefault_library=static" in command
    assert "-Dstrip=false" in command
    assert "-Dc_thread_count=7" in command
    assert "-Dcpp_thread_count=7" in command
    assert command[command.index("--warnlevel") + 1] == "1"
    assert "-Db_lto=true" in command


def test_meson_compile_command_uses_parallel_jobs(monkeypatch):
    monkeypatch.setattr(meson_handler, "BUILD_JOBS", 11)
    monkeypatch.setattr(meson_handler, "MESON_EXTRA_COMPILE_ARGS", ("--verbose",))

    command = meson_handler.meson_compile_command("libpng")

    assert command == [
        "meson",
        "compile",
        "-C",
        str(meson_handler.build_dir_for("libpng")),
        "-j",
        "11",
        "--verbose",
    ]


def test_find_meson_executables_filters_intermediate_object_files(monkeypatch):
    monkeypatch.setattr(
        meson_handler,
        "get_executables",
        lambda directory: [
            str(directory / "demo" / "demo"),
            str(directory / "demo" / "libdemo.a"),
            str(directory / "demo" / "libdemo_objlib.a"),
            str(directory / "demo" / "libdemo.a.p" / "demo.c.o"),
            str(directory / "demo" / "demo.p" / "main.c.o"),
        ],
    )
    monkeypatch.setattr(
        meson_handler.os,
        "access",
        lambda path, mode: str(path).endswith("/demo"),
    )

    executables = meson_handler.find_meson_executables("demo")

    assert executables == [
        str(meson_handler.build_dir_for("demo") / "subprojects" / "demo" / "demo"),
        str(meson_handler.build_dir_for("demo") / "subprojects" / "demo" / "libdemo.a"),
    ]


def test_vcpkg_install_command_uses_clean_build_roots(monkeypatch):
    monkeypatch.setattr(vcpkg_handler, "VCPKG_EXTRA_INSTALL_ARGS", ("--head",))
    monkeypatch.setattr(vcpkg_handler, "VCPKG_KEEP_GOING", True)
    monkeypatch.setattr(vcpkg_handler, "VCPKG_DEFAULT_TRIPLET", "arm64-osx")

    command = vcpkg_handler.vcpkg_install_command("openssl")

    assert command[0] == "./vcpkg"
    assert command[1:4] == ["install", "--keep-going", "--clean-after-build"]
    assert "--triplet=arm64-osx" in command
    assert any(part.startswith("--x-buildtrees-root=") for part in command)
    assert any(part.startswith("--x-packages-root=") for part in command)
    assert any(part.startswith("--x-install-root=") for part in command)
    assert command[-2:] == ["openssl", "--head"]


def test_vcpkg_build_sets_parallelism(monkeypatch):
    captured = {}

    def fake_run_command(command, *, cwd=None, env=None, project_name=""):
        captured["command"] = command
        captured["cwd"] = cwd
        captured["env"] = env
        captured["project_name"] = project_name

        class _Result:
            returncode = 0

        return _Result()

    monkeypatch.setattr(vcpkg_handler, "BUILD_JOBS", 13)
    monkeypatch.setattr(vcpkg_handler, "run_command", fake_run_command)
    monkeypatch.setattr(
        vcpkg_handler,
        "vcpkg_install_command",
        lambda project_name: ["./vcpkg", "install", project_name],
    )

    result = vcpkg_handler.vcpkg_build("sqlite3")

    assert result.returncode == 0
    assert captured["command"] == ["./vcpkg", "install", "sqlite3"]
    assert captured["project_name"] == "sqlite3"
    assert captured["env"]["VCPKG_MAX_CONCURRENCY"] == "13"


def test_find_vcpkg_executables_reads_installed_listfiles(tmp_path, monkeypatch):
    vcpkg_root = tmp_path / "vcpkg"
    info_dir = vcpkg_root / "installed" / "vcpkg" / "info"
    triplet_root = vcpkg_root / "installed" / "arm64-osx"
    info_dir.mkdir(parents=True)
    (triplet_root / "lib").mkdir(parents=True)
    (triplet_root / "debug" / "lib").mkdir(parents=True)
    (triplet_root / "share" / "zlib").mkdir(parents=True)

    release_lib = triplet_root / "lib" / "libz.a"
    debug_lib = triplet_root / "debug" / "lib" / "libz.a"
    cmake_file = triplet_root / "share" / "zlib" / "ZLIBConfig.cmake"
    release_lib.write_bytes(b"!<arch>\n")
    debug_lib.write_bytes(b"!<arch>\n")
    cmake_file.write_text("cmake", encoding="utf-8")
    (info_dir / "zlib_1.3.2_arm64-osx.list").write_text(
        "\n".join(
            [
                "arm64-osx/lib/libz.a",
                "arm64-osx/debug/lib/libz.a",
                "arm64-osx/share/zlib/ZLIBConfig.cmake",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(vcpkg_handler, "VCPKG_LOCATION", vcpkg_root)
    monkeypatch.setattr(vcpkg_handler, "VCPKG_ARCH_OS", "arm64-osx")
    monkeypatch.setattr(vcpkg_handler, "VCPKG_DEFAULT_TRIPLET", "arm64-osx")
    monkeypatch.setattr(vcpkg_handler, "get_executables", lambda directory: [])

    executables = vcpkg_handler.find_vcpkg_executables("zlib")

    assert executables == [str(debug_lib), str(release_lib)]


def test_cargo_build_command_uses_locked_release_and_feature_flags(monkeypatch):
    monkeypatch.setattr(cargo_handler, "CARGO_EXECUTABLE", "cargo")
    monkeypatch.setattr(cargo_handler, "CARGO_EXTRA_BUILD_ARGS", ("--timings",))
    spec = cargo_handler.CargoProjectSpec(
        crate="hexyl",
        version="0.17.0",
        features=("clipboard",),
        default_features=False,
        bins=("hexyl",),
        target="aarch64-apple-darwin",
    )

    command = cargo_handler.cargo_build_command(
        "/tmp/hexyl/Cargo.toml",
        spec,
        locked=True,
        frozen=True,
    )

    assert command[:3] == ["cargo", "build", "--message-format=json-render-diagnostics"]
    assert "--release" in command
    assert "--locked" in command
    assert "--frozen" in command
    assert "--no-default-features" in command
    assert command[command.index("--features") + 1] == "clipboard"
    assert command[command.index("--bin") + 1] == "hexyl"
    assert command[command.index("--target") + 1] == "aarch64-apple-darwin"
    assert command[-1] == "--timings"


def test_cargo_metadata_command_uses_supported_flags_only():
    spec = cargo_handler.CargoProjectSpec(
        crate="choose",
        version="1.3.7",
        features=("regex",),
        default_features=False,
        bins=("choose",),
        package="choose",
        target="aarch64-apple-darwin",
    )

    command = cargo_handler.cargo_metadata_command(
        "/tmp/choose/Cargo.toml",
        spec,
        locked=True,
    )

    assert command[0] == cargo_handler.CARGO_EXECUTABLE
    assert command[1] == "metadata"
    assert "--locked" in command
    assert "--no-default-features" in command
    assert command[command.index("--features") + 1] == "regex"
    assert command[command.index("--filter-platform") + 1] == "aarch64-apple-darwin"
    assert "--bin" not in command
    assert "--package" not in command
