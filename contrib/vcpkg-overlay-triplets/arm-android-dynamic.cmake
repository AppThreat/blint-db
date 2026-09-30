# arm-android (armeabi-v7a, NEON on) with VCPKG_LIBRARY_LINKAGE=dynamic.
# Mirrors the community triplets/arm-android.cmake at the pinned vcpkg
# revision (63bb8e44c1) except for the linkage line - and without that
# triplet's ANDROID_ARM_NEON=OFF, which NDK r27+ rejects ("Disabling Neon
# is no longer supported"): every armeabi-v7a build with a current NDK is a
# NEON build, which is what newer vcpkg revisions name arm-neon-android.
set(VCPKG_TARGET_ARCHITECTURE arm)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
set(VCPKG_CMAKE_SYSTEM_NAME Android)
set(VCPKG_CMAKE_SYSTEM_VERSION 28)
set(VCPKG_MAKE_BUILD_TRIPLET "--host=armv7a-linux-androideabi")
set(VCPKG_CMAKE_CONFIGURE_OPTIONS -DANDROID_ABI=armeabi-v7a)

# nettle's bundled gnulib getopt does not compile as C23, clang's default.
set(VCPKG_C_FLAGS "-std=gnu17")
