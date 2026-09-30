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
# Host prerequisites (A8 N1, measured): autoconf-archive and gnu-sed from
# Homebrew (libidn2/libtasn1 autoreconf; libunistring's declared.sh
# rejects BSD sed), and the gnu-sed libexec/gnubin directory on PATH.
# The gmp overlay port (contrib/vcpkg-overlay-ports) drops --enable-cxx
# and names the compiler target on CC for the Android x86 triplet; the
# overlay triplets pin -std=gnu17 (NDK r28's clang defaults to C23,
# where nettle's bundled gnulib getopt redeclares conflict).
#
# Each triplet writes <db-file>.<triplet>.metadata.json with the NDK
# revision, API level and per-port build outcomes.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_FILE="${1:?usage: build_android_corpus.sh <db-file> [triplet ...]}"
shift || true
TRIPLETS=("${@:-arm64-android-dynamic}")

export BLINT_DB_VCPKG_OVERLAY_TRIPLETS="${REPO_ROOT}/contrib/vcpkg-overlay-triplets"
export BLINT_DB_VCPKG_INSTALL_ARGS="--overlay-ports=${REPO_ROOT}/contrib/vcpkg-overlay-ports"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point at the NDK}"

# libunistring's declared.sh insists on GNU sed.
if [ -x /opt/homebrew/opt/gnu-sed/libexec/gnubin/sed ]; then
  PATH="/opt/homebrew/opt/gnu-sed/libexec/gnubin:${PATH}"
  export PATH
fi

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
