"""The vcpkg build flow records the Android target, not the host (I1).

add_project_vcpkg_db is driven with a stubbed vcpkg build and a real
archive on disk, capturing what the ingest calls receive. Paths use
tmp_path/pathlib, so no platform-specific behaviour is assumed.
"""

from pathlib import Path


def _stub_build_module(monkeypatch, tmp_path: Path, *, triplet: str, ndk: Path | None):
    """Patch the vcpkg build flow around one static archive on disk."""
    from blint_db.projects_compiler import vcpkg as vcpkg_compiler

    archive = tmp_path / "packages" / f"zstd_{triplet}" / "lib" / "libzstd.a"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(b"!<arch>\n")

    class _Result:
        returncode = 0

    monkeypatch.setattr(vcpkg_compiler, "vcpkg_build", lambda name: _Result())
    monkeypatch.setattr(vcpkg_compiler, "find_vcpkg_executables", lambda name: [str(archive)])
    monkeypatch.setattr(vcpkg_compiler, "VCPKG_DEFAULT_TRIPLET", triplet)
    monkeypatch.setattr(vcpkg_compiler, "SYSTEM", "osx")
    monkeypatch.setattr(vcpkg_compiler, "ARCH", "arm64")
    monkeypatch.setattr(vcpkg_compiler, "ANDROID_NDK_HOME", str(ndk) if ndk else None)

    captured: dict[str, dict] = {"binary": {}, "members": {}}

    def fake_ingest_binary_file(path, **kwargs):
        captured["binary"] = kwargs
        return {"binary_id": 1}

    def fake_ingest_archive_members(path, **kwargs):
        captured["members"] = kwargs
        return []

    monkeypatch.setattr(vcpkg_compiler, "ingest_binary_file", fake_ingest_binary_file)
    monkeypatch.setattr(
        vcpkg_compiler, "ingest_archive_members", fake_ingest_archive_members
    )
    return vcpkg_compiler, captured


def _ndk_with_source_properties(tmp_path: Path) -> Path:
    ndk = tmp_path / "ndk"
    ndk.mkdir(exist_ok=True)
    (ndk / "source.properties").write_text(
        "Pkg.Desc = Android NDK\nPkg.Revision = 28.2.13676358\n", encoding="utf-8"
    )
    return ndk


def test_android_build_rows_carry_target_and_ndk_facts(tmp_path, monkeypatch):
    ndk = _ndk_with_source_properties(tmp_path)
    compiler, captured = _stub_build_module(
        monkeypatch, tmp_path, triplet="arm64-android-dynamic", ndk=ndk
    )

    compiler.add_project_vcpkg_db("zstd", None)

    for call in ("binary", "members"):
        kwargs = captured[call]
        assert kwargs["target_os"] == "android"
        assert kwargs["target_arch"] == "arm64"
        assert kwargs["target_triplet"] == "arm64-android-dynamic"
        android = kwargs["build_metadata"]["android"]
        assert android["ndk_revision"] == "28.2.13676358"
        assert android["abi"] == "arm64-v8a"
        assert android["ndk_home"] == str(ndk)
    # The member ingest receives the same target fields as the whole-file
    # ingest, so member rows describe the build they came from.
    assert captured["members"]["archive_name"] == "libzstd.a"


def test_android_build_rows_without_ndk_record_unknown(tmp_path, monkeypatch):
    compiler, captured = _stub_build_module(
        monkeypatch, tmp_path, triplet="arm64-android", ndk=None
    )

    compiler.add_project_vcpkg_db("zstd", None)

    android = captured["binary"]["build_metadata"]["android"]
    assert android["ndk_revision"] is None
    assert android["ndk_home"] is None


def test_host_triplet_build_rows_keep_host_derived_target(tmp_path, monkeypatch):
    compiler, captured = _stub_build_module(
        monkeypatch, tmp_path, triplet="arm64-osx", ndk=_ndk_with_source_properties(tmp_path)
    )

    compiler.add_project_vcpkg_db("zstd", None)

    kwargs = captured["binary"]
    assert kwargs["target_os"] == "osx"
    assert kwargs["target_arch"] == "arm64"
    # A host build records no Android facts.
    assert "android" not in (kwargs["build_metadata"] or {})


def test_port_version_reads_every_vcpkg_schema_field():
    from blint_db.projects_compiler.vcpkg import _port_version

    assert _port_version({"version": "1.5.7"}) == "1.5.7"
    assert _port_version({"version-semver": "3.13.3"}) == "3.13.3"
    assert _port_version({"version-string": "1.3.7"}) == "1.3.7"
    assert _port_version({"version-date": "2024-08-13"}) == "2024-08-13"
    assert _port_version({"version": None, "version-semver": "3.13.3"}) == "3.13.3"
    assert _port_version({}) is None
