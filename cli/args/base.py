from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from pipeline.scanners import DEFAULT_SCANNERS_CSV, SUPPORTED_SCANNERS


def add_base_args(
    parser: argparse.ArgumentParser,
    *,
    root_dir: Path,
    repo_keys: Sequence[str],
) -> None:
    """Register CLI flags that are shared across multiple modes.

    This includes:
    - mode selection
    - scanner selection
    - suite layout (suite_root/suite_id/case_id)
    - repo selection
    - execution knobs
    """

    parser.add_argument(
        "--mode",
        choices=["scan", "benchmark", "suite", "analyze", "import"],
        help=(
            "scan = one tool, benchmark = multiple tools, suite = multi-case suite run (interactive/CSV/worktrees/replay file), "
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
        default=str(root_dir / "runs" / "suites"),
        help="Base directory for suite runs (default: runs/suites).",
    )
    parser.add_argument(
        "--suite-id",
        "--bundle-id",
        dest="suite_id",
        help=(
            "Suite run id to create/use. If omitted in scan/benchmark, a new UTC timestamp is used. "
            "In analyze mode, omit to use LATEST (recommended), or pass --suite-id latest explicitly."
        ),
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

    # Repo selection
    parser.add_argument(
        "--repo-key", choices=sorted(repo_keys), help="Preset repo key (recommended)"
    )
    parser.add_argument("--repo-url", help="Custom git repo URL")
    parser.add_argument("--repo-path", help="Local repo path (skip clone)")

    parser.add_argument(
        "--dry-run", action="store_true", help="Print commands but do not execute"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress scanner stdout/stderr (not recommended for debugging)",
    )

    parser.add_argument(
        "--runs-repo-name",
        help=(
            "(analyze mode) Override the repo directory name under runs/<tool>/. "
            "By default we derive it from the repo URL (e.g., juice-shop) or local folder name."
        ),
    )
