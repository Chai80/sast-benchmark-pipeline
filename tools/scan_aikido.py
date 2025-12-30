#!/usr/bin/env python3
"""tools/scan_aikido.py

Stable Aikido entrypoint used by pipeline/core.py.

Thin shim:
  - parse CLI args
  - delegate to tools.aikido.cli_entry(...)

Implementation lives in tools/aikido/ (Option B).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.aikido import cli_entry


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Aikido scan and export issues for a connected repo.")
    parser.add_argument(
        "--git-ref",
        required=False,
        help="Repo name or GitHub URL fragment (e.g. 'juice-shop' or 'Chai80/juice-shop')",
    )
    parser.add_argument("--output-root", default="runs/aikido", help="Output root folder (default: runs/aikido)")
    parser.add_argument("--skip-trigger", action="store_true", help="Skip triggering a scan; export latest issues.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cli_entry(git_ref=args.git_ref, output_root=args.output_root, skip_trigger=args.skip_trigger)


if __name__ == "__main__":
    main()
