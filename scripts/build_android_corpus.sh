#!/usr/bin/env bash
# Build the Android NDK corpus database (I2, wave A6.2).
#
# Builds every port of blint_db/inputs/vcpkg-android-corpus.csv with vcpkg's
# Android triplets and the dynamic-linkage overlay triplets committed under
# contrib/vcpkg-overlay-triplets, then ingests the artifacts into one v3
# database per ABI. The linkage decision (I1) chose dynamic: a static .a
# stores its symbols under symtab_sources a stripped app library never
# offers, and never matches (measured on zstd and sqlite3); a dynamic .so
# computes the same llvm_target_tuple as the app libraries, so the strict
# first-pass filter admits it.
#
# Usage: scripts/build_android_corpus.sh <db-file> [triplet ...]
#   triplet defaults to arm64-android-dynamic. Build arm64 first; the other
#   ABIs (arm-android-dynamic, x64-android-dynamic, x86-android-dynamic)
#   only after the arm64 database has been measured (wave A6.3's J0).
#
# Environment:
#   ANDROID_NDK_HOME  the NDK vcpkg compiles with (required by vcpkg's
#                      android toolchain); its source.properties revision
#                      lands in provenance and the Builds rows
#   BLINT_DB_BOOTSTRAP_PATH  where the vcpkg checkout lives (default ./temp)
#
# The database is NOT committed; its path, size, row counts and sha256 are
# recorded in the I2 commit's gate block, and the run metadata sidecar
# (<db>.metadata.json) carries the per-port build status.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_FILE="${1:?usage: build_android_corpus.sh <db-file> [triplet ...]}"
shift || true
TRIPLETS=("${@:-arm64-android-dynamic}")

export BLINT_DB_VCPKG_OVERLAY_TRIPLETS="${REPO_ROOT}/contrib/vcpkg-overlay-triplets"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point at the NDK (vcpkg's android toolchain requires it)}"

PORTS="$(python3 -c '
import csv, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    print(" ".join(row["port"] for row in csv.DictReader(fh)))
' "${REPO_ROOT}/blint_db/inputs/vcpkg-android-corpus.csv")"

for triplet in "${TRIPLETS[@]}"; do
  echo "=== triplet ${triplet} $(date -u +%H:%M:%S)"
  BLINT_DB_VCPKG_TRIPLET="${triplet}" blint-db --db-file "${DB_FILE}" \
    --run-metadata-file "${DB_FILE}.${triplet}.metadata.json" build-vcpkg \
    --retain-build-artifacts -s ${PORTS}
  # build-vcpkg compacts the database; the per-triplet metadata sidecar
  # carries the per-port outcomes, so a port that fails to build is
  # recorded there with its stage and message, not dropped.
done
echo "done: ${DB_FILE}"
