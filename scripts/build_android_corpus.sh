#!/usr/bin/env bash
# Build the Android NDK corpus: every port in
# blint_db/inputs/vcpkg-android-corpus.csv, for each triplet given, into one
# v3 database.
#
# The triplets are the dynamic-linkage overlays in
# contrib/vcpkg-overlay-triplets. A static archive's members store their
# names as symtab symbols, which a stripped app library's dynamic-symbol
# query never meets, so only shared libraries match.
#
# Usage: scripts/build_android_corpus.sh <db-file> [triplet ...]
#   triplet defaults to arm64-android-dynamic; the others are
#   arm-android-dynamic, x64-android-dynamic and x86-android-dynamic.
#
# Environment:
#   ANDROID_NDK_HOME  the NDK vcpkg's Android toolchain compiles with
#
# Each triplet writes <db-file>.<triplet>.metadata.json with the NDK
# revision, API level and per-port build outcomes.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_FILE="${1:?usage: build_android_corpus.sh <db-file> [triplet ...]}"
shift || true
TRIPLETS=("${@:-arm64-android-dynamic}")

export BLINT_DB_VCPKG_OVERLAY_TRIPLETS="${REPO_ROOT}/contrib/vcpkg-overlay-triplets"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point at the NDK}"

PORTS="$(python3 -c '
import csv, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    print(" ".join(row["port"] for row in csv.DictReader(fh)))
' "${REPO_ROOT}/blint_db/inputs/vcpkg-android-corpus.csv")"

for triplet in "${TRIPLETS[@]}"; do
  echo "=== triplet ${triplet} $(date -u +%H:%M:%S)"
  # shellcheck disable=SC2086 # PORTS is a word list
  BLINT_DB_VCPKG_TRIPLET="${triplet}" blint-db --db-file "${DB_FILE}" \
    --run-metadata-file "${DB_FILE}.${triplet}.metadata.json" build-vcpkg \
    --retain-build-artifacts -s ${PORTS}
done
echo "done: ${DB_FILE}"
