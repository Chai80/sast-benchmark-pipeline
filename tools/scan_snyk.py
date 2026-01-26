#!/usr/bin/env python3
"""tools/scan_snyk.py

Stable Snyk entrypoint used by pipeline/core.py.

Thin shim:
  - parse CLI args
  - call tools.snyk.execute(...)
  - print artifact paths

Implementation lives in tools/snyk/ (Option B).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.snyk import execute


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run Snyk Code scan and normalize results.")
    p.add_argument("--repo-url", help="Git repo URL to scan.")
    p.add_argument("--repo-path", help="Local repo path to scan (skip clone).")
    p.add_argument(
        "--repos-dir", default="repos", help="Repos base dir (default: repos)."
    )
    p.add_argument(
        "--output-root", default="runs/snyk", help="Output root (default: runs/snyk)."
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    paths, _meta = execute(
        repo_url=args.repo_url,
        repo_path=args.repo_path,
        repos_dir=args.repos_dir,
        output_root=args.output_root,
    )
    print("📄 Raw SARIF saved to:", paths.raw_sarif)
    print("📄 Metadata saved to:", paths.metadata)
    print("📄 Normalized JSON saved to:", paths.normalized)


if __name__ == "__main__":
    main()
