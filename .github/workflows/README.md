<!--
SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>

SPDX-License-Identifier: MIT
-->

# Blint-db Github Workflow 

## Description
GitHub workflows for `blint-db` build a SQLite database named `blint.db` and publish corpus snapshots for the Meson, vcpkg, Homebrew, Cargo, and Conan pipelines.

There are five build systems, `build-meson`, `build-vcpkg`, `build-homebrew`, `build-cargo`, and `build-conan`.
The Meson smoke-test workflow now runs on GitHub-hosted Linux and macOS runners so end-to-end subset validation does not require self-hosted infrastructure, while Homebrew and Cargo macOS builds target self-hosted runners with the local toolchains they need.

## Details

- `blint-db` already pins `blint` through `tool.uv.sources`, so the workflows let `uv` install `blint` directly from the configured source.
- Disassembly-enabled workflows install LLVM 18 and then export the extra compiler/linker environment needed for `nyxstone` before running `uv sync`.
- On macOS, `NYXSTONE_LLVM_PREFIX` alone is not enough for `nyxstone` 0.1.1; the workflows also set `CXXFLAGS=-std=c++17` plus `LDFLAGS` pointing at the Homebrew library directory.
- Each ecosystem build writes a provenance sidecar JSON (for example `blint.metadata.json`) and ORAS publishes it alongside `blint.db`.
- Homebrew smoke builds use the curated formula list in `blint_db/inputs/homebrew-formulas.csv` so the first macOS corpus spans C, C++, Rust, Go, and Swift formulas.
- Cargo builds use the pinned crate list in `blint_db/inputs/cargo-crates.csv`, fetch exact crate tarballs from crates.io, verify published SHA-256 checksums, and record Cargo/Rust tool versions plus build provenance in the sidecar metadata. Repeated `crate@version` rows are supported through named `feature_profile` selectors.
- Conan builds use the curated package list in `blint_db/inputs/conan-center-packages.csv`, resolve package graphs inside an isolated `CONAN_HOME`, deploy binary artifacts into a build-local directory, and record remote/profile/settings/options provenance in the sidecar metadata.
- Conan smoke coverage runs on both hosted Linux and hosted macOS in `build-conan-tst.yml`, while full publication uses dedicated Linux and macOS workflows.
- The Conan curated manifest intentionally includes both `shared-release` and `static-debug` selectors so workflow smoke runs catch profile-sensitive drift.
- Curated Homebrew/Cargo/Conan manifests can be regenerated with the helper scripts under `scripts/` using analytics/search inputs when available.
- Full-corpus Linux workflows still use the existing long-running runner pool, but the smoke-test jobs are a good template for future Windows and broader GitHub-hosted expansion.


### Future Improvements
- Add a Windows Meson smoke-test once the compiler/bootstrap step is standardized for `wrapdb` packages on GitHub-hosted runners.
- Reuse a shared composite action for Python + LLVM + Homebrew setup across the ecosystem workflows.
