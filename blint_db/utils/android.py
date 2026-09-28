# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Android triplet facts for vcpkg cross builds.

At the pinned vcpkg revision (63bb8e44c1) the armeabi-v7a triplet is the
community ``arm-android``; newer revisions call it ``arm-neon-android``, so
both map to the same ABI. The dynamic-linkage overlay triplets the Android
corpus builds with append ``-dynamic`` (contrib/vcpkg-overlay-triplets).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# vcpkg triplet -> Android ABI (the spelling blint's abi qualifier uses).
ANDROID_TRIPLET_ABIS = {
    "arm64-android": "arm64-v8a",
    "arm-android": "armeabi-v7a",
    "arm-neon-android": "armeabi-v7a",
    "x64-android": "x86_64",
    "x86-android": "x86",
}

_SYSTEM_VERSION_RE = re.compile(r"set\s*\(\s*VCPKG_CMAKE_SYSTEM_VERSION\s+(\d+)\s*\)")
_NDK_REVISION_RE = re.compile(r"^Pkg\.Revision\s*=\s*(\S+)", re.MULTILINE)


def _base_triplet(triplet: str | None) -> str:
    return (triplet or "").removesuffix("-dynamic")


def android_triplet_abi(triplet: str | None) -> str | None:
    """The Android ABI a triplet builds for, or None for non-Android ones."""
    return ANDROID_TRIPLET_ABIS.get(_base_triplet(triplet))


def is_android_triplet(triplet: str | None) -> bool:
    return android_triplet_abi(triplet) is not None


def triplet_target_os_arch(
    triplet: str | None, *, host_os: str, host_arch: str
) -> tuple[str, str]:
    """The (target_os, target_arch) a build of this triplet records.

    An Android triplet names its own target (``arm64-android`` ->
    android/arm64); any other triplet is a host build and keeps the host pair.
    """
    if is_android_triplet(triplet):
        return "android", _base_triplet(triplet).split("-", 1)[0]
    return host_os, host_arch


def read_ndk_revision(ndk_home: str | os.PathLike | None) -> str | None:
    """``Pkg.Revision`` from ``<ndk>/source.properties``; None when unreadable."""
    if not ndk_home:
        return None
    try:
        content = (Path(ndk_home) / "source.properties").read_text(encoding="utf-8")
    except OSError:
        return None
    match = _NDK_REVISION_RE.search(content)
    return match.group(1) if match else None


def read_triplet_api_level(
    triplet: str | None,
    vcpkg_location: str | os.PathLike | None,
    overlay_triplets: str | os.PathLike | None = None,
) -> int | None:
    """The triplet's ``VCPKG_CMAKE_SYSTEM_VERSION``, the API level the NDK
    toolchain builds for.

    The overlay directory is searched first, then triplets/ and
    triplets/community/, which is the order vcpkg resolves them in.
    """
    if not triplet or not vcpkg_location:
        return None
    roots = [Path(overlay_triplets)] if overlay_triplets else []
    roots += [Path(vcpkg_location) / "triplets", Path(vcpkg_location) / "triplets" / "community"]
    for root in roots:
        try:
            content = (root / f"{triplet}.cmake").read_text(encoding="utf-8")
        except OSError:
            continue
        if match := _SYSTEM_VERSION_RE.search(content):
            return int(match.group(1))
    return None


def android_build_facts(
    triplet: str | None,
    ndk_home: str | os.PathLike | None,
    vcpkg_location: str | os.PathLike | None,
    overlay_triplets: str | os.PathLike | None = None,
) -> dict | None:
    """The NDK and ABI facts an Android build records, or None for host builds."""
    abi = android_triplet_abi(triplet)
    if abi is None:
        return None
    return {
        "abi": abi,
        "api_level": read_triplet_api_level(triplet, vcpkg_location, overlay_triplets),
        "ndk_home": str(ndk_home) if ndk_home else None,
        "ndk_revision": read_ndk_revision(ndk_home),
    }
