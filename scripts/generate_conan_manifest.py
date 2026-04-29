#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from blint_db.utils.manifest_generation import generate_conan_manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a curated Conan Center CSV from ranked seed references or conan search resolution."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of package references to include.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("blint_db/inputs/conan-center-packages.csv"),
        help="Destination CSV file.",
    )
    parser.add_argument(
        "--reference",
        action="append",
        dest="references",
        help="Explicit Conan reference or package name seed. Repeatable.",
    )
    parser.add_argument(
        "--remote",
        default="conancenter",
        help="Conan remote to query when --resolve-with-conan is enabled.",
    )
    parser.add_argument(
        "--conan-executable",
        default="conan",
        help="Conan executable to invoke when resolving package names.",
    )
    parser.add_argument(
        "--resolve-with-conan",
        action="store_true",
        help="Resolve package names or refresh references using 'conan search'.",
    )
    parser.add_argument(
        "--no-static-debug",
        action="store_true",
        help="Do not emit the static-debug profile rows.",
    )
    parser.add_argument(
        "--no-shared-release",
        action="store_true",
        help="Do not emit the shared-release profile rows.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    output = generate_conan_manifest(
        limit=max(1, args.limit),
        output_file=args.output,
        references=args.references,
        remote=args.remote,
        conan_executable=args.conan_executable,
        resolve_with_conan=args.resolve_with_conan,
        include_static_debug=not args.no_static_debug,
        include_shared_release=not args.no_shared_release,
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
