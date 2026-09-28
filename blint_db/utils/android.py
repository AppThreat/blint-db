# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Android triplet facts for vcpkg cross builds.

The four Android ABIs map onto vcpkg triplets; at the pinned vcpkg revision
(63bb8e44c1) the armeabi-v7a triplet is ``arm-android`` (community; its
NEON-off flag predates NDK r27, which rejects it - the dynamic overlay
drops it, and newer vcpkg revisions renamed the triplet
``arm-neon-android``), so both spellings map to the same ABI here. The dynamic-linkage overlay triplets
used for the corpus append ``-dynamic`` (contrib/vcpkg-overlay-triplets).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# vcpkg triplet -> Android ABI (the blint/cyclonedx qualifier spelling).
ANDROID_TRIPLET_ABIS = {
    "arm64-android": "arm64-v8a",
    "arm-android": "armeabi-v7a",
    "arm-neon-android": "armeabi-v7a",
    "x64-android": "x86_64",
    "x86-android": "x86",
}

# Triplet prefix -> (target_os, target_arch) for the Builds table. A
# non-android triplet keeps the host-derived values the caller already had.
_TRIPLET_TARGETS = {
    "arm64-android": ("android", "arm64"),
    "arm-android": ("android", "arm"),
    "arm-neon-android": ("android", "arm"),
    "x64-android": ("android", "x64"),
    "x86-android": ("android", "x86"),
}

_SYSTEM_VERSION_RE = re.compile(r"set\s*\(\s*VCPKG_CMAKE_SYSTEM_VERSION\s+(\d+)\s*\)")
_NDK_REVISION_RE = re.compile(r"^Pkg\.Revision\s*=\s*(\S+)", re.MULTILINE)


def is_android_triplet(triplet: str | None) -> bool:
    """Whether the triplet targets Android (including -dynamic overlays)."""
    if not triplet:
        return False
    base = triplet.removesuffix("-dynamic")
    return base in ANDROID_TRIPLET_ABIS


def android_triplet_abi(triplet: str | None) -> str | None:
    """The Android ABI name for a triplet, or None for non-android ones."""
    if not triplet:
        return None
    return ANDROID_TRIPLET_ABIS.get(triplet.removesuffix("-dynamic"))


def triplet_target_os_arch(
    triplet: str | None, *, host_os: str, host_arch: str
) -> tuple[str, str]:
    """(target_os, target_arch) a build of this triplet must record.

    Android triplets say android/arm64/android/x86...; anything else is a
    host build and keeps the host-derived pair the caller passed.
    """
    if triplet:
        target = _TRIPLET_TARGETS.get(triplet.removesuffix("-dynamic"))
        if target:
            return target
    return host_os, host_arch


def read_ndk_revision(ndk_home: str | os.PathLike | None) -> str | None:
    """The NDK revision from ``<ndk>/source.properties`` (``Pkg.Revision``).

    None when the NDK location is not set or carries no readable
    source.properties - recorded as unknown, never guessed.
    """
    if not ndk_home:
        return None
    properties = Path(ndk_home) / "source.properties"
    try:
        content = properties.read_text(encoding="utf-8")
    except OSError:
        return None
    match = _NDK_REVISION_RE.search(content)
    return match.group(1) if match else None


def read_triplet_api_level(
    triplet: str | None,
    vcpkg_location: str | os.PathLike | None,
    overlay_triplets: str | os.PathLike | None = None,
) -> int | None:
    """The Android API level a triplet builds for.

    Read from the triplet's ``VCPKG_CMAKE_SYSTEM_VERSION`` - the NDK
    toolchain's ANDROID_PLATFORM comes from it - searching the overlay
    directory first, then triplets/ and triplets/community/. None when the
    triplet cannot be found or states no version.
    """
    if not triplet or not vcpkg_location:
        return None
    roots: list[Path] = []
    if overlay_triplets:
        roots.append(Path(overlay_triplets))
    roots.append(Path(vcpkg_location) / "triplets")
    roots.append(Path(vcpkg_location) / "triplets" / "community")
    for root in roots:
        candidate = root / f"{triplet}.cmake"
        try:
            content = candidate.read_text(encoding="utf-8")
        except OSError:
            continue
        match = _SYSTEM_VERSION_RE.search(content)
        if match:
            return int(match.group(1))
    return None
