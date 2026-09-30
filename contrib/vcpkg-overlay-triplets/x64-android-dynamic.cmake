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

# nettle's bundled gnulib getopt does not compile as C23, clang's default.
set(VCPKG_C_FLAGS "-std=gnu17")
