#!/usr/bin/env bash
# Rebuild the committed sample database tests/data/blintdb-sample.db.
#
# The sample is the query-contract fixture between this repository and blint
# (tests/test_blintdb_contract.py runs blint's real lookup queries against
# it), so it must stay rebuildable from pinned inputs:
#   - the wrapdb checkout is pinned by WRAPDB_COMMIT_HASH in blint_db/config.py
#   - blint itself is pinned by the git source in pyproject.toml / uv.lock
#   - the selectors below are the sample's corpus: zlib + bzip2 + c-ares,
#     symbol-only (no disassembly), shared libraries, unstripped
#
# Selector choice: the plan's suggested trio was zlib+bzip2+zstd, but zstd's
# build emits two symlink-twin dylibs (identical sha256, ~2.6 MB of metadata
# each) plus two large CLI binaries, which pushed the database past 10 MB.
# The smallest measured three-project set that keeps distinct symbol spaces
# is zlib+bzip2+c-ares at ~6.6 MB (fmt measures ~8.9 MB). The size target and
# the measurements are recorded in the D0.3 commit message.
#
# Usage: scripts/build_sample_db.sh [output-dir]
#   output-dir defaults to tests/data. The script never commits; review the
#   diff (the .db is binary, so check the metadata sidecar and row counts).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-${REPO_ROOT}/tests/data}"
SAMPLE_DB="${OUTPUT_DIR}/blintdb-sample.db"
SAMPLE_METADATA="${OUTPUT_DIR}/blintdb-sample.metadata.json"
# Fixed bootstrap path, deliberately not $TMPDIR: the wrapdb clone is
# pinned by WRAPDB_COMMIT_HASH, and the unstripped debug builds embed the
# build directory into the binaries and their STAB symbols, so a constant
# absolute path is what makes two rebuilds converge (see the commit message
# for the residual per-link variance). Build artifacts are not needed once
# the database is written.
BOOTSTRAP="/tmp/blintdb-sample-bootstrap"
rm -rf "${BOOTSTRAP}"
trap 'rm -rf "${BOOTSTRAP}"' EXIT

cd "${REPO_ROOT}"
mkdir -p "${OUTPUT_DIR}"

# BLINT_DB_MESON_STRIP=0 keeps symbols in the built libraries (the sample is
# symbol-only by design; a stripped corpus would have nothing to query).
BLINT_DB_BOOTSTRAP_PATH="${BOOTSTRAP}" \
BLINT_DB_MESON_STRIP=0 \
uv run blint-db \
    --clean-start \
    --db-file "${SAMPLE_DB}" \
    --run-metadata-file "${SAMPLE_METADATA}" \
    build-meson -s zlib bzip2 c-ares

uv run python - "${SAMPLE_DB}" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
meta = dict(connection.execute("SELECT key, value FROM SchemaMeta").fetchall())
counts = {
    table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    for table in ("Projects", "Builds", "Binaries", "Symbols", "FunctionFingerprints")
}
print(f"schema: {meta}")
print(f"counts: {counts}")
assert meta.get("schema_family") == "blint-db", meta
assert meta.get("schema_version") == "3", meta
assert counts["Projects"] == 3, counts
assert counts["Symbols"] > 0, counts
assert counts["FunctionFingerprints"] == 0, "sample must stay symbol-only"
connection.close()
PY

echo "Sample database written to ${SAMPLE_DB}"
echo "Review the diff, then commit ${SAMPLE_DB}, ${SAMPLE_METADATA} and the"
echo ".license sidecar together."
