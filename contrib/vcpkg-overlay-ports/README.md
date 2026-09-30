# vcpkg overlay ports (Android corpus)

`gmp` — a copy of the builtin port at the pinned revision (63bb8e44c1)
with `--enable-cxx` dropped. The C++ bindings (`libgmpxx`) are the only
part that fails to cross-build for the Android triplets: gmp's configure
bakes a host-probe result into the link line and `ld.lld` dies with
`unable to find library -lSystem` (a macOS framework, not an NDK one).
Nothing the Android corpus needs links gmpxx — nettle and libgnutls use
the C library only — so the corpus recipe passes
`--overlay-ports=contrib/vcpkg-overlay-ports`
(`BLINT_DB_VCPKG_INSTALL_ARGS`) and records this directory as part of
its provenance.
