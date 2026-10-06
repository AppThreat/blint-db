# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT
"""Ingest build artifacts in an isolated worker process.

blint's parser (and the disassembler behind ``--disassemble``) holds hundreds
of MB of native and Python memory per large binary, and the process allocator
retains those arenas after the metadata is released. Ingesting a whole corpus
in one process therefore ratchets resident memory up towards the sum of the
largest per-binary peaks — a 368-project Meson corpus drove a 30GB host into
the OOM killer this way, at 24GB RSS. Running each project's ingestion in a
short-lived worker returns that memory to the OS when the worker exits.

The worker prints one JSON document (a list of per-file results) on stdout and
exits 0 as long as the run itself did not crash; per-file ingestion errors are
reported in the results, mirroring the in-process behaviour of logging the
error and continuing with the next binary.
"""
from __future__ import annotations

import argparse
import json
import sys

from blint_db.ingest import ingest_binary_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blint-db-ingest-worker",
        description="Ingest binary files into blint-db from an isolated process.",
    )
    parser.add_argument("files", nargs="+", help="Binary files to ingest")
    parser.add_argument("--db-file", dest="db_file")
    parser.add_argument("--project-name", dest="project_name", required=True)
    parser.add_argument("--project-purl", dest="project_purl")
    parser.add_argument("--ecosystem", dest="ecosystem")
    parser.add_argument("--build-system", dest="build_system", default="manual")
    parser.add_argument("--project-metadata-json", dest="project_metadata_json")
    parser.add_argument("--target-os", dest="target_os")
    parser.add_argument("--target-arch", dest="target_arch")
    parser.add_argument("--build-mode", dest="build_mode")
    parser.add_argument("--strip-status", dest="strip_status")
    parser.add_argument("--build-metadata-json", dest="build_metadata_json")
    parser.add_argument("--relative-to", dest="relative_to")
    parser.add_argument(
        "--disassemble",
        dest="disassemble",
        action="store_true",
        default=False,
    )
    return parser


def _load_optional_json(raw: str | None):
    if not raw:
        return None
    return json.loads(raw)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    results = []
    for binary_file in args.files:
        try:
            result = ingest_binary_file(
                binary_file,
                db_file=args.db_file,
                project_name=args.project_name,
                project_purl=args.project_purl,
                ecosystem=args.ecosystem,
                project_metadata=_load_optional_json(args.project_metadata_json),
                build_system=args.build_system,
                target_os=args.target_os,
                target_arch=args.target_arch,
                build_mode=args.build_mode,
                strip_status=args.strip_status,
                build_metadata=_load_optional_json(args.build_metadata_json),
                relative_to=args.relative_to,
                disassemble=args.disassemble,
            )
            results.append({"file": binary_file, "status": "ok", "result": result})
        except Exception as exc:  # pylint: disable=broad-exception-caught
            results.append(
                {
                    "file": binary_file,
                    "status": "error",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
    json.dump(results, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
