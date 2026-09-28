# arm-android (armeabi-v7a, NEON off) with VCPKG_LIBRARY_LINKAGE=dynamic.
# Mirrors the community triplets/arm-android.cmake at the pinned vcpkg
# revision (63bb8e44c1) except for the linkage line. Later vcpkg revisions
# renamed this triplet arm-neon-android.
set(VCPKG_TARGET_ARCHITECTURE arm)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
set(VCPKG_CMAKE_SYSTEM_NAME Android)
set(VCPKG_CMAKE_SYSTEM_VERSION 28)
set(VCPKG_MAKE_BUILD_TRIPLET "--host=armv7a-linux-androideabi")
set(VCPKG_CMAKE_CONFIGURE_OPTIONS -DANDROID_ABI=armeabi-v7a -DANDROID_ARM_NEON=OFF)
