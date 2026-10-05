<!--
SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>

SPDX-License-Identifier: MIT
-->

# Sourcing binaries and building your own database

The published blint-db databases are built from Meson, vcpkg, Homebrew, Conan
Center and crates.io. None of them covers the binaries most people actually
scan: the `.so` inside an Android APK, the `.dll` inside a Windows portable
zip, the `.dylib` inside a macOS app bundle. blint 4 reads all of those
containers natively, and this document shows how to source their members and
turn them into a database your own `blint sbom --use-blintdb` runs can use.

The rule that shapes everything below: **`blint-db` ingests one binary file
at a time** (`blint-db ingest -i <file>`). blint 4 walks APK/IPA/MSIX/MSI
containers during its own scan, but the database builder wants the members,
so unpack the container first and ingest the interesting files.

## What is worth ingesting

A database row is useful to blint only when it carries evidence another
binary could match:

- ELF shared libraries and executables — dynamic symbols, symtab symbols,
  version nodes (`.so`, native Android libraries, Linux binaries)
- Mach-O libraries, frameworks and executables (`.dylib`, app binaries,
  iOS framework members)
- PE executables, DLLs and drivers (`.exe`, `.dll`, `.sys`), including .NET
  single-file bundles
- static archives (`.a`, `.lib`) — with `--archive-members` every object
  member becomes its own row, which powers member-level matching

Stripped binaries are fine: the dynamic-symbol table survives stripping and
is the primary match key. Debug symbols add symtab evidence but are not
required.

## Android native libraries

### From the F-Droid store

F-Droid is the cleanest source: every APK is built from source that is
published, versioned and reproducibly re-buildable, and the download URLs
are stable.

- Download pattern: `https://f-droid.org/repo/<package>_<versionCode>.apk`.
  When a newer release supersedes the version you pinned, the file moves to
  `https://f-droid.org/archive/<package>_<versionCode>.apk`, which keeps
  every version ever published.
- Version resolution: `https://f-droid.org/api/v1/packages/<package>` lists
  every published `versionCode`/`versionName` pair.
- **Split APKs**: many apps publish one APK per ABI instead of one
  multi-ABI APK, distinguished only by `versionCode`. VLC 3.7.1 is four
  APKs (`13070105`–`13070108`, one per ABI), Saber 1.36.1 is three
  (`1360101` arm64-v8a, `1360102` armeabi-v7a, `1360103` x86_64). Ingest
  all of them; each APK's `lib/<abi>/` directory tells you which ABI it
  carries.
- Inside the APK only `lib/<abi>/*.so` at the archive root is an ABI
  directory — the same rule blint 4's Android reader applies. The current
  ABIs are `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`; `armeabi`, `mips`
  and `mips64` are retired.
- Splits and bundles are one logical app: deduplicate libraries by sha256
  before ingesting, exactly as blint deduplicates them inside one app.

This repository ships the full pipeline as a worked example:

- `blint_db/inputs/fdroid-apps.csv` — the curated app list (the F-Droid
  store client itself, VLC, OsmAnd, Element, Fennec, Termux, NewPipe,
  Organic Maps, App Manager, Saber, LocalSend), one row per APK with the
  pinned `version_code`
- `scripts/build_fdroid_corpus.py` — downloads each APK (repo first,
  archive fallback), extracts `lib/<abi>/*.so` with the ABI-directory and
  budget rules above, dedupes by sha256, and ingests every unique library
  under a project named after the app, recording the APK URL, version code
  and ABI as build provenance
- `.github/workflows/build-android-fdroid.yml` — the example GitHub
  Actions workflow that runs the script on `ubuntu-latest`, asserts the
  database is non-empty, uploads it as an artifact and publishes it with
  ORAS

Local run:

```bash
uv run python scripts/build_fdroid_corpus.py --db-file ./fdroid.db
# a quick smoke run, one app, one ABI:
uv run python scripts/build_fdroid_corpus.py --db-file ./fdroid.db \
  --only org.videolan.vlc --abis arm64-v8a
```

The apps were not chosen at random: they are the tier-2 corpus blint 4's
Android identification was validated against, including the deliberate
no-match controls (NewPipe, Organic Maps) — a corpus needs binaries that
should *not* match, or you cannot tell a working matcher from a
never-failing one.

### Other Android sources

- **AARs from Maven Central** — native Android libraries ship as AAR
  artifacts with `jni/<abi>/*.so` inside. An AAR is a zip:
  `unzip react-android.aar -d react-android` then ingest the `jni/`
  members. This is how you get framework runtimes (React Native's hermes,
  Flutter engine artifacts) at exact published versions.
- **Android platform images** — the system `.so` files (`libcrypto.so`
  BoringSSL, `libc++.so`, APEX libraries) come from emulator system
  images: `adb root` + `adb pull /system/lib64` etc. blint's own tier-0
  corpus scripts (`tests/scripts/android/` in the blint repository)
  automate this; `google_apis` images are the rootable ones.
- **Building with the NDK** — `scripts/build_android_corpus.sh` in this
  repository cross-compiles the vcpkg Android corpus with the NDK for
  every ABI, using the dynamic-linkage overlay triplets in
  `contrib/vcpkg-overlay-triplets`. Use it when you need known-pure
  builds of specific libraries (zstd, sqlite3, openssl, ...) rather than
  whatever an app happened to bundle.
- **XAPK / split bundles** — an XAPK is a zip of APKs; extract the APK
  members first, then their `lib/<abi>/` directories.

## Windows PE binaries

- **Portable archives from GitHub releases** — the friendliest source.
  Portable `.zip`/`.7z` releases of 7-Zip, ImageMagick, curl-for-win,
  Rufus and similar projects contain the `.exe` and `.dll` ready to
  ingest. Prefer projects that build from public source.
- **MSYS2 packages** — `https://packages.msys2.org` serves mingw-w64
  builds of openssl, libcurl, sqlite and hundreds more as
  `.pkg.tar.zst`. Extract with `bsdtar -xf` or `7z x`; the payload is
  `mingw64/bin/*.dll` and `mingw64/lib/*.dll.a`.
- **NuGet packages** — a `.nupkg` is a zip; native packages carry
  `runtimes/win-x64/native/*.dll`. blint 4 parses NuGet directly during
  scans; for database building, extract and ingest the native members.
- **Installers** — MSI databases extract with `msiextract` (msitools) or
  `lessmsi x`; 7z self-extracting installers and plain `.7z`/`.zip`
  archives extract with `7z x`. MSIX/Appx packages (what winget mostly
  distributes) are zips: `7z x app.msix` then ingest the `.exe`/`.dll`
  members; blint 4 verifies their blockmaps during scans.
- **Static import libraries** — a `.lib` archive ingests with
  `--archive-members` so every object member is matchable individually.
- **vcpkg on a Windows host** — `build-vcpkg` builds and ingests vcpkg
  ports directly; see `.github/workflows/build-vcpkg.yml`.

Group files into projects the way you will query them: one project per
upstream package (`7-zip`, `imagemagick`), not per archive, and record the
download URL in the build metadata so a match can be traced to its source.

## Apple Mach-O binaries

- **Homebrew bottles** — every bottle is a plain tarball published at a
  stable digest URL (see the `bottle` block of any formula at
  formulae.brew.sh); it contains `lib/*.dylib` and the linked tools.
  Bottles extract on any OS, so a Linux CI runner can build a darwin
  corpus this way. On a Mac, `build-homebrew` does the build-and-ingest
  in one command.
- **Release DMGs of open-source apps** — `hdiutil attach app.dmg` on
  macOS or `7z x app.dmg` anywhere else, then ingest
  `<App>.app/Contents/MacOS/*` and every `Contents/Frameworks/*.dylib`
  member. blint 4 walks app bundles, embedded frameworks, extensions and
  Swift metadata during scans; for the database, the leaf binaries are
  the rows.
- **iOS IPAs** — an IPA is a zip containing `Payload/<App>.app`; the app
  binary and its `Frameworks/*.framework/*` members are Mach-O.
  Open-source iOS apps (Kodi, VLC, Nextcloud) publish IPAs on their
  GitHub releases.
- **Xcode / Swift builds** — build the open-source project and ingest the
  products; record the Xcode version and deployment target as build
  metadata.

## Building the database

Single-binary ingestion with explicit provenance:

```bash
blint-db --db-file my.db ingest \
  --project-name vlc-android \
  --project-purl "pkg:generic/org.videolan.vlc@3.7.1" \
  --ecosystem fdroid \
  --build-system gradle \
  --target-os android --target-arch arm64 \
  -i ./extracted/lib/arm64-v8a/libvlc.so
```

Repeat per binary; `ingest` upserts the project by name, so all members of
one app or package land under one project and the match aggregation in
`lookup_project_symbol_matches` works across them. Add `--disassemble`
(extends the dependency set with nyxstone; see
[Disassembly requirements](../README.md#disassembly-requirements)) to
populate `FunctionFingerprints` for deep matching, and
`--archive-members` for static archives.

For anything larger than a handful of files, generate the metadata first
and ingest the JSON — the parse step is the slow part, and this split lets
you retry ingestion without re-parsing. A normal scan writes
`<name>-metadata.json` into its reports directory:

```bash
blint -i ./libvlc.so -o ./reports   # writes ./reports/libvlc.so-metadata.json
blint-db --db-file my.db ingest \
  --project-name vlc-android \
  --metadata-file ./reports/libvlc.so-metadata.json
```

Conventions that pay off later:

- `--ecosystem` / `--build-system` record where the binary came from
  (`fdroid`/`gradle`, `homebrew`, `nuget`, ...); they are the first filter
  when debugging a surprising match.
- `--target-os` / `--target-arch` keep ABIs and platforms separable; blint
  filters Android queries by binary type, so do not mix `lib/<abi>` trees
  into one build row.
- Store the source URL and version in build metadata — the provenance
  sidecar (`--run-metadata-file`) makes the whole run reproducible.

## Using your database with blint 4

blint looks for a file named `blint.db` inside `BLINTDB_HOME` (falling back to `blint-v4.db`):

```bash
mkdir -p ~/.blintdb-home && cp my.db ~/.blintdb-home/blint.db
export BLINTDB_HOME=~/.blintdb-home

blint sbom -i app.apk -o sbom.cdx.json --use-blintdb      # symbol matching
blint sbom -i app.apk -o sbom.cdx.json --use-blintdb --deep  # + function hashes
```

Databases with schema version 2 and 3 are both read; the similarity-hash
layer activates per database when its columns are populated. On Android
input, every unique `.so` sha256 in the APK is matched against the
database once, and a match replaces the library's identity only when the
library's `DT_SONAME` is one of the project's own library names —
otherwise the match is recorded as a nested (statically bundled) copy,
which is the difference between "bundles VLC" and "is VLC".

A worked result from the pipeline above, run on the VLC arm64 APK against
a database built from F-Droid VLC 3.7.1:

```
- org.videolan.vlc pkg:generic/org.videolan.vlc@3.7.1
    blint:blintdb:project_purl = pkg:generic/org.videolan.vlc@3.7.1
    blint:blintdb:score = 730.0
    blint:blintdb:soname_match = libmla.so
    blint:identification:evidence = org.videolan.vlc: blintdb symbol match
      (symbols): 694 symbols (e.g. JNI_OnLoad, JNI_OnUnload, ...)
```

`libmla.so` — a binary with no package metadata of its own — is identified
as the VLC media library from 694 matched symbols, while the vendored
`libvlc.so` is separately identified as `pkg:github/videolan/vlc@3.0.23`
from its release banner. Versions come from the artifact's strings, never
from the database row, so a stale corpus pin cannot invent a wrong
version.

## Licensing and hygiene

- Ingest only binaries you may redistribute or keep the database private.
  Everything in `fdroid-apps.csv` is published under free-software
  licenses by F-Droid; GitHub-release portable archives and Homebrew
  bottles are usually fine; store-bought MSIX and App Store IPAs are not.
- Record provenance for every row (source URL, version, ABI). A database
  that cannot say where a symbol table came from cannot be trusted as
  evidence.
- No scraping: F-Droid's repo, archive and API are the supported
  interfaces, and the build respects them; the same ground rule blint's
  own corpus work follows.
- Hostile inputs: the extraction in `build_fdroid_corpus.py` applies the
  same budgets blint 4 applies to APK members (per-entry and cumulative
  caps, basename-only destinations), so a crafted APK cannot fill a disk
  or escape the extraction directory.
