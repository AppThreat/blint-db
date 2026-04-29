#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from blint_db.utils.manifest_generation import generate_cargo_manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a curated Cargo crate CSV from crates.io search and download rankings."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of crates to include.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("blint_db/inputs/cargo-crates.csv"),
        help="Destination CSV file.",
    )
    parser.add_argument(
        "--query",
        help="Optional crates.io search query.",
    )
    parser.add_argument(
        "--category",
        help="Optional crates.io category filter, for example command-line-utilities.",
    )
    parser.add_argument(
        "--include-dev-profile",
        action="store_true",
        help="Duplicate generated entries with a dev/debug profile selector.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    output = generate_cargo_manifest(
        limit=max(1, args.limit),
        output_file=args.output,
        query=args.query,
        category=args.category,
        include_dev_profile=args.include_dev_profile,
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
