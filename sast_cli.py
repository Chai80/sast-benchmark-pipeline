#!/usr/bin/env python3
"""sast_cli.py

Top-level CLI wrapper for the Durinn SAST benchmarking pipeline.

Modes
-----
1) scan
   - run one scanner against one repo
2) benchmark
   - run multiple scanners against one repo
   - (default) run the analysis suite after scans
3) suite
   - run multiple scanners across multiple cases (many repos / branches)
   - suites can be built interactively, loaded from CSV/worktrees, or replayed from an optional Python replay file (.py)
4) analyze
   - compute cross-tool metrics from existing normalized runs
5) import
   - import legacy runs/<tool>/... outputs into suite layout (runs/suites/<suite_id>/...)

Suite layout (recommended)
--------------------------
By default this CLI writes *everything* for a run into a single **suite** folder
with one **case** folder per target:

  runs/suites/<suite_id>/
    cases/<case_id>/
      case.json
      tool_runs/<tool>/<run_id>/...
      analysis/...
      gt/...

This keeps the output tree readable and makes it easy to share a specific
experiment run (or rerun analysis) without hunting across many directories.

Use --case-id when you want an explicit case identifier (e.g., branch-per-case
micro-suites).

Examples
--------
# Benchmark Juice Shop into a new suite (then run analysis suite)
python sast_cli.py --mode benchmark --repo-key juice_shop --scanners semgrep,snyk,sonar

# Same, but pick a specific suite id
python sast_cli.py --mode benchmark --repo-key juice_shop --suite-id 20260104T013000Z

# Analyze the latest suite for a target
python sast_cli.py --mode analyze --metric suite --repo-key juice_shop --suite-id latest

# Legacy behavior (write directly to runs/<tool>/...)
python sast_cli.py --mode benchmark --repo-key juice_shop --no-suite

# Run a multi-case suite from a Python replay file (usually generated under runs/suites/<suite_id>/replay/)
python sast_cli.py --mode suite --suite-file runs/suites/<suite_id>/replay/replay_suite.py --suite-id <new_suite_id>
"""

from __future__ import annotations

import argparse
from typing import Dict

from cli.args.analyze import add_analyze_args
from cli.args.base import add_base_args
from cli.args.import_mode import add_import_mode_args
from cli.args.suite import add_suite_args
from cli.args.tool_overrides import add_tool_override_args
from cli.dispatch import dispatch
from pipeline.core import ROOT_DIR as PIPELINE_ROOT_DIR
from pipeline.wiring import build_pipeline

ROOT_DIR = PIPELINE_ROOT_DIR  # repo root

# Replace/add your preset repos here
REPOS: Dict[str, Dict[str, str]] = {
    "juice_shop": {
        "label": "Juice Shop",
        "repo_url": "https://github.com/juice-shop/juice-shop.git",
    },
    "webgoat": {
        "label": "WebGoat",
        "repo_url": "https://github.com/WebGoat/WebGoat.git",
    },
    "dvwa": {"label": "DVWA", "repo_url": "https://github.com/digininja/DVWA.git"},
    "owasp_benchmark": {
        "label": "OWASP BenchmarkJava",
        "repo_url": "https://github.com/OWASP/BenchmarkJava.git",
    },
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Top-level CLI for SAST pipeline (Durinn).")

    add_base_args(parser, root_dir=ROOT_DIR, repo_keys=sorted(REPOS.keys()))
    add_suite_args(parser)
    add_analyze_args(parser, root_dir=ROOT_DIR)
    add_import_mode_args(parser)
    add_tool_override_args(parser)

    return parser


def parse_args() -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args()

    # Backwards-compatible attribute aliases (legacy bundle terminology).
    # Flags --bundle-root/--bundle-id/--bundle-path/--no-bundle remain supported;
    # internal code should prefer suite_* / case_* naming.
    args.bundle_root = args.suite_root
    args.bundle_id = args.suite_id
    args.bundle_path = args.case_path
    args.no_bundle = args.no_suite

    return args



def main() -> None:
    args = parse_args()

    # Build the pipeline facade (also loads .env by default).
    pipeline = build_pipeline(load_dotenv=True)

    exit_code = dispatch(args, pipeline, repo_registry=REPOS)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
