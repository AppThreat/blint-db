#!/bin/bash
# Prepares a vcpkg checkout for musl hosts (Alpine and friends).
#
# vcpkg downloads glibc-linked cmake/ninja tool binaries that cannot run
# on musl. With VCPKG_FORCE_SYSTEM_BINARIES=1 vcpkg uses the system tools
# instead, but refuses any cmake older than the version recorded in
# scripts/vcpkg-tools.json. This script clones vcpkg at the blint-db
# pinned revision and lowers the recorded linux cmake version to the
# system cmake so the force-system-binaries path works.
#
# Usage (inside the musl container, before `blint-db build-vcpkg`):
#   export BLINT_DB_BOOTSTRAP_PATH=/tmp/blint-db-temp
#   contrib/vcpkg-musl-prepare.sh "" "$BLINT_DB_BOOTSTRAP_PATH/vcpkg"
#   export VCPKG_FORCE_SYSTEM_BINARIES=1
#   export BLINT_DB_VCPKG_TRIPLET=arm64-musl
#   export BLINT_DB_VCPKG_OVERLAY_TRIPLETS=$PWD/contrib/vcpkg-overlay-triplets
#
set -euo pipefail

VCPKG_COMMIT="${1:-19780d9cdf84d0944cf9a318666703b89ab6629c}"
VCPKG_DIR="${2:-$(pwd)/vcpkg}"

if [ ! -d "$VCPKG_DIR" ]; then
    git clone https://github.com/microsoft/vcpkg.git "$VCPKG_DIR"
fi
git -C "$VCPKG_DIR" checkout -q "$VCPKG_COMMIT"

SYSTEM_CMAKE="$(cmake --version 2>/dev/null | head -1 | sed 's/^cmake version //')"
if [ -z "$SYSTEM_CMAKE" ]; then
    echo "cmake not found on PATH; install cmake first" >&2
    exit 1
fi

sed -i "s/\"version\": \"4.4.3\"/\"version\": \"${SYSTEM_CMAKE}\"/g" \
    "$VCPKG_DIR/scripts/vcpkg-tools.json"

echo "vcpkg at $VCPKG_DIR pinned to $VCPKG_COMMIT"
echo "linux cmake requirement lowered to system cmake $SYSTEM_CMAKE"
echo "remember to export VCPKG_FORCE_SYSTEM_BINARIES=1 for the build"
