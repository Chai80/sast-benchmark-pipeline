#!/usr/bin/env python3
"""tools/scan_sonar.py

Stable SonarCloud entrypoint used by pipeline/core.py.

This file intentionally stays thin:
  - parse CLI args
  - call tools.sonar.runner.execute(...)
  - print artifact paths

Implementation lives in tools/sonar/runner.py and tools/sonar/{api,normalize,rules}.py.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Minimal bootstrap so this file can be executed directly while using
# clean package imports.
#
# IMPORTANT: This must run BEFORE importing local packages like `sast_benchmark`
# when the script is invoked as: `python tools/scan_sonar.py ...`
# ---------------------------------------------------------------------------
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.sonar.runner import execute


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run SonarCloud scan on a repo and save JSON + metadata + normalized output."
    )
    p.add_argument("--repo-url", required=False, help="Git repo URL to scan.")
    p.add_argument("--repo-path", required=False, help="Local repo path to scan (skip clone).")
    p.add_argument("--repos-dir", default="repos", help="Repos base dir. Default: repos.")
    p.add_argument("--output-root", default="runs/sonar", help="Output root. Default: runs/sonar.")
    p.add_argument("--project-key", default=None, help="Optional SonarCloud project key override.")
    p.add_argument("--java-binaries", default="", help="Optional sonar.java.binaries path(s).")
    p.add_argument(
        "--skip-scan",
        action="store_true",
        help="Skip sonar-scanner execution and only fetch issues.",
    )
    args = p.parse_args()

    if args.repo_url and args.repo_path:
        raise SystemExit("Provide only one of --repo-url or --repo-path.")

    if not args.repo_url and not args.repo_path:
        raise SystemExit("Provide --repo-url or --repo-path.")

    return args


# ---------------------------------------------------------------------------
# Sonar config (env)
# ---------------------------------------------------------------------------


def main() -> None:
    args = parse_args()

    paths, _meta = execute(
        repo_url=args.repo_url,
        repo_path=args.repo_path,
        repos_dir=args.repos_dir,
        output_root=args.output_root,
        project_key=args.project_key,
        java_binaries=args.java_binaries,
        skip_scan=args.skip_scan,
    )
    print("📄 Issues JSON saved to:", paths.raw_results)
    print("📄 Metadata saved to:", paths.metadata)
    print("📄 Normalized JSON saved to:", paths.normalized)


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as e:
        print(f"❌ {e}", file=sys.stderr)
        raise SystemExit(127)
