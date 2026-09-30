set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_CMAKE_SYSTEM_NAME Darwin)
set(VCPKG_OSX_ARCHITECTURES arm64)

# A8 N1 host-triplet override: Apple clang's default C standard is gnu23,
# where nettle's bundled gnulib getopt redeclares (`extern int getopt ();`,
# now "(void)"-typed) conflict with Darwin's unistd.h prototype and the
# HOST tools build fails. gnu17 is what the port was written against.
set(VCPKG_C_FLAGS "-std=gnu17")
set(VCPKG_CXX_FLAGS "-std=gnu++17")
