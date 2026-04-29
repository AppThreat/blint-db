#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from blint_db.utils.manifest_generation import generate_homebrew_manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a curated Homebrew formula CSV from top analytics or explicit formula names."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of formulas to include.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("blint_db/inputs/homebrew-formulas.csv"),
        help="Destination CSV file.",
    )
    parser.add_argument(
        "--formula",
        action="append",
        dest="formulae",
        help="Explicit formula name to include. Repeatable. If omitted, Homebrew analytics is used.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    output = generate_homebrew_manifest(
        limit=max(1, args.limit),
        output_file=args.output,
        formula_names=args.formulae,
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
