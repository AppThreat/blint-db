# x64-android (x86_64) with VCPKG_LIBRARY_LINKAGE=dynamic.
# Mirrors the builtin triplets/x64-android.cmake at the pinned vcpkg
# revision (63bb8e44c1) except for the linkage line.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
set(VCPKG_CMAKE_SYSTEM_NAME Android)
set(VCPKG_CMAKE_SYSTEM_VERSION 28)
set(VCPKG_MAKE_BUILD_TRIPLET "--host=x86_64-linux-android")
set(VCPKG_CMAKE_CONFIGURE_OPTIONS -DANDROID_ABI=x86_64)

# A8 N1: NDK r28's clang defaults to C23, where nettle's bundled gnulib
# getopt redeclares (`extern int getopt ();`, now "(void)"-typed) conflict
# with the sysroot's prototype. gnu17 is what the port was written against.
set(VCPKG_C_FLAGS "-std=gnu17")
set(VCPKG_CXX_FLAGS "-std=gnu++17")
