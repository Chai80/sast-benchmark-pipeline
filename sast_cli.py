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
   - suite definitions are supplied as Python (.py) (or built interactively)
4) analyze
   - compute cross-tool metrics from existing normalized runs

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

# Run a multi-case suite from a Python definition
python sast_cli.py --mode suite --suite-file examples/suite_inputs/example_suite.py
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict

from cli.dispatch import dispatch
from pipeline.core import ROOT_DIR as PIPELINE_ROOT_DIR
from pipeline.scanners import DEFAULT_SCANNERS_CSV, SUPPORTED_SCANNERS
from pipeline.wiring import build_pipeline

ROOT_DIR = PIPELINE_ROOT_DIR  # repo root

# Replace/add your preset repos here
REPOS: Dict[str, Dict[str, str]] = {
    "juice_shop": {"label": "Juice Shop", "repo_url": "https://github.com/juice-shop/juice-shop.git"},
    "webgoat": {"label": "WebGoat", "repo_url": "https://github.com/WebGoat/WebGoat.git"},
    "dvwa": {"label": "DVWA", "repo_url": "https://github.com/digininja/DVWA.git"},
    "owasp_benchmark": {"label": "OWASP BenchmarkJava", "repo_url": "https://github.com/OWASP/BenchmarkJava.git"},
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Top-level CLI for SAST pipeline (Durinn).")

    parser.add_argument(
        "--mode",
        choices=["scan", "benchmark", "suite", "analyze"],
        help=(
            "scan = one tool, benchmark = multiple tools, suite = multi-case suite run (optional YAML), "
            "analyze = compute metrics from existing runs"
        ),
    )
    parser.add_argument(
        "--scanner",
        choices=sorted(SUPPORTED_SCANNERS),
        help="(scan mode) Which scanner to run",
    )
    parser.add_argument(
        "--scanners",
        help=f"(benchmark|suite mode) Comma-separated scanners (default: {DEFAULT_SCANNERS_CSV})",
    )

    parser.add_argument(
        "--track",
        type=str,
        default=None,
        help=(
            "Optional benchmark track to scope scoring/execution (e.g. sast|sca|iac|secrets). "
            "If omitted, scoring considers all GT tracks present in the repo."
        ),
    )

    # Suite layout
    parser.add_argument(
        "--suite-root",
        "--bundle-root",
        dest="suite_root",
        default=str(ROOT_DIR / "runs" / "suites"),
        help="Base directory for suite runs (default: runs/suites).",
    )
    parser.add_argument(
        "--suite-id",
        "--bundle-id",
        dest="suite_id",
        help=(
            "Suite run id to create/use. If omitted in scan/benchmark, a new UTC timestamp is used. "
            "In analyze mode you can pass 'latest'."
        ),
    )

    parser.add_argument(
        "--suite-file",
        dest="suite_file",
        help=(
            "(suite mode) Optional Python suite definition (.py exporting SUITE_DEF or SUITE_RAW). If omitted, you can build a suite interactively "
            "or use --cases-from / --worktrees-root to load many cases quickly. "
            "suite.json/case.json/run.json are always written as the ground-truth record of what actually ran."
        ),
    )

    parser.add_argument(
        "--cases-from",
        dest="cases_from",
        help=(
            "(suite mode) Load cases from a CSV file (columns: case_id,repo_path[,label][,branch][,track][,tags_json]). "
            "Recommended locations: examples/suite_inputs/ (portable) or inputs/suite_inputs/ (local, ignored). "
            "Useful for CI runs or when you need an explicit case list."
        ),
    )

    parser.add_argument(
        "--worktrees-root",
        dest="worktrees_root",
        help=(
            "(suite mode) Import cases by discovering git worktrees/checkouts under this folder (recommended for branch-per-case suites). "
            "Each git checkout becomes one case. Example: repos/worktrees/durinn-owasp2021-python-micro-suite"
        ),
    )

    parser.add_argument(
        "--max-cases",
        dest="max_cases",
        type=int,
        default=None,
        help="(suite mode) When loading cases from --cases-from/--worktrees-root, only include the first N cases.",
    )

    parser.add_argument(
        "--case-id",
        dest="case_id",
        help=(
            "Override the case id within the suite (folder name under runs/suites/<suite_id>/cases/<case_id>/). "
            "If omitted, we derive it from the repo name. Useful for branch-per-case micro-suites."
        ),
    )
    parser.add_argument(
        "--case-path",
        "--bundle-path",
        dest="case_path",
        help="(analyze mode) Path to an existing case dir (overrides --suite-root/--suite-id).",
    )
    parser.add_argument(
        "--no-suite",
        "--no-bundle",
        dest="no_suite",
        action="store_true",
        help="Disable suite layout and use legacy runs/<tool>/<repo>/<run_id>/... paths.",
    )
    parser.add_argument(
        "--skip-analysis",
        action="store_true",
        help="(benchmark|suite mode) Skip the analysis suite step (scans only).",
    )

    # Analysis / metrics
    parser.add_argument(
        "--metric",
        choices=["hotspots", "suite"],
        help="(analyze mode) Metric to compute (hotspots|suite)",
    )
    parser.add_argument(
        "--tools",
        help=f"(analyze mode) Comma-separated tools to include (default: {DEFAULT_SCANNERS_CSV})",
    )
    parser.add_argument(
        "--runs-dir",
        default=str(ROOT_DIR / "runs"),
        help="(analyze mode, legacy) Base runs directory (default: <repo_root>/runs)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="(analyze mode) Output format (default: text)",
    )
    parser.add_argument(
        "--out",
        help="(analyze mode) Optional output path to write the JSON report",
    )
    parser.add_argument(
        "--analysis-out-dir",
        help=(
            "(analyze mode, suite) Optional output directory for suite artifacts. "
            "If using suites, default is <case>/analysis/."
        ),
    )
    parser.add_argument(
        "--tolerance",
        type=int,
        default=3,
        help="(analysis suite) Line clustering tolerance for location matrix (default: 3)",
    )
    parser.add_argument(
        "--analysis-filter",
        choices=["security", "all"],
        default="security",
        help="(analysis suite) Finding filter mode (default: security)",
    )
    parser.add_argument(
        "--max-unique",
        type=int,
        default=25,
        help="(analyze hotspots) For text output, show up to N unique files per tool (default: 25)",
    )
    parser.add_argument(
        "--runs-repo-name",
        help=(
            "(analyze mode) Override the repo directory name under runs/<tool>/. "
            "By default we derive it from the repo URL (e.g., juice-shop) or local folder name."
        ),
    )

    # Repo selection
    parser.add_argument("--repo-key", choices=sorted(REPOS.keys()), help="Preset repo key (recommended)")
    parser.add_argument("--repo-url", help="Custom git repo URL")
    parser.add_argument("--repo-path", help="Local repo path (skip clone)")

    # Sonar-specific
    parser.add_argument(
        "--sonar-project-key",
        help="(sonar only) Override SonarCloud project key. If omitted, we derive ORG_<repo_id>.",
    )
    # Aikido-specific
    parser.add_argument(
        "--aikido-git-ref",
        help=(
            "(aikido only) Override the git reference passed to scan_aikido.py as --git-ref. "
            "Use this when running aikido with --repo-path and no --repo-url (e.g., suite branch clones/worktrees). "
            "Example: Chai80/durinn-owasp2021-python-micro-suite"
        ),
    )

    parser.add_argument("--dry-run", action="store_true", help="Print commands but do not execute")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress scanner stdout/stderr (not recommended for debugging)",
    )

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
