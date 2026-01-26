#!/usr/bin/env python3
"""tools/scan_semgrep.py

Stable Semgrep entrypoint used by pipeline/core.py.

This file intentionally stays thin:
  - parse CLI args
  - call tools.semgrep.execute(...)
  - print artifact paths

Implementation lives in tools/semgrep/{runner,normalize}.py (Option B).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Minimal bootstrap so direct execution works:
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.semgrep import execute


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Run Semgrep scan and normalize results.")
    ap.add_argument("--repo-url", required=False, help="Git repo URL to scan.")
    ap.add_argument("--repo-path", required=False, help="Local repo path to scan (skip clone).")
    ap.add_argument("--config", default="auto", help="Semgrep config. Default: auto.")
    ap.add_argument(
        "--output-root",
        default="runs/semgrep",
        help="Output root. Default: runs/semgrep.",
    )
    ap.add_argument("--repos-dir", default="repos", help="Repos base dir. Default: repos.")
    ap.add_argument(
        "--timeout-seconds",
        type=int,
        default=0,
        help="Semgrep timeout. 0 = no timeout.",
    )

    ns = ap.parse_args()

    # Preserve prior interactive behavior: prompt if neither is provided.
    if not ns.repo_url and not ns.repo_path:
        ns.repo_url = input("Enter Git repo URL to scan: ").strip()

    if ns.repo_url and ns.repo_path:
        raise SystemExit("Provide only one of --repo-url or --repo-path.")

    if not ns.repo_url and not ns.repo_path:
        raise SystemExit("Provide --repo-url or --repo-path.")

    return ns


def main() -> None:
    args = parse_args()
    paths, _meta = execute(
        repo_url=args.repo_url,
        repo_path=args.repo_path,
        repos_dir=args.repos_dir,
        output_root=args.output_root,
        config=args.config,
        timeout_seconds=args.timeout_seconds,
    )
    print("📄 Raw JSON saved to:", paths.raw_results)
    print("📄 Metadata saved to:", paths.metadata)
    print("📄 Normalized JSON saved to:", paths.normalized)


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as e:
        print(f"❌ {e}", file=sys.stderr)
        raise SystemExit(127)
