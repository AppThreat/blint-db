# arm64-musl: linux/arm64 on musl libc (Alpine and friends).
# vcpkg ships no musl triplet, so this overlay fills the gap for the
# blint-db musl corpus. Run it on a musl host (or in a musl container)
# so the system compiler targets musl natively; static linkage is the
# conventional choice for musl ports and keeps builds free of ABI
# surprises across musl releases.
set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)
set(VCPKG_BUILD_TYPE release)
