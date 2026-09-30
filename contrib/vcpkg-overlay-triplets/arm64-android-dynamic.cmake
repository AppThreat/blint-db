# arm64-android (arm64-v8a) with VCPKG_LIBRARY_LINKAGE=dynamic.
# Mirrors the builtin triplets/arm64-android.cmake at the pinned vcpkg
# revision (63bb8e44c1) except for the linkage line: a shared library is
# what an Android app bundles, and what blint's symbol query matches on.
set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
set(VCPKG_CMAKE_SYSTEM_NAME Android)
set(VCPKG_CMAKE_SYSTEM_VERSION 28)
set(VCPKG_MAKE_BUILD_TRIPLET "--host=aarch64-linux-android")
set(VCPKG_CMAKE_CONFIGURE_OPTIONS -DANDROID_ABI=arm64-v8a)

# A8 N1: NDK r28's clang defaults to C23, where nettle's bundled gnulib
# getopt redeclares (`extern int getopt ();`, now "(void)"-typed) conflict
# with the sysroot's prototype. gnu17 is what the port was written against.
set(VCPKG_C_FLAGS "-std=gnu17")
set(VCPKG_CXX_FLAGS "-std=gnu++17")
