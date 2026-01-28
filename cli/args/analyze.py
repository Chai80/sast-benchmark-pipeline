from __future__ import annotations

import argparse
from pathlib import Path

from pipeline.scanners import DEFAULT_SCANNERS_CSV


def add_analyze_args(parser: argparse.ArgumentParser, *, root_dir: Path) -> None:
    """Register CLI flags used by analyze mode and the analysis suite.

    Many of these flags also influence the post-scan analysis step that runs
    after benchmark/suite modes.
    """

    # Analysis / metrics
    parser.add_argument(
        "--metric",
        choices=["hotspots", "suite", "suite_compare"],
        help="(analyze mode) Metric to compute (hotspots|suite|suite_compare)",
    )

    # Suite-to-suite compare (analyze mode)
    parser.add_argument(
        "--compare-suites",
        dest="compare_suites",
        default=None,
        help=(
            "(analyze mode, --metric suite_compare) Compare two suites and write a drift report. "
            "Format: 'A,B'. Each value may be a suite_id folder name under --suite-root or a special ref: "
            "latest|previous. Example: --compare-suites latest,previous or --compare-suites 20260101T...,20260105T..."
        ),
    )
    parser.add_argument(
        "--compare-latest-previous",
        dest="compare_latest_previous",
        action="store_true",
        help=(
            "(analyze mode, --metric suite_compare) Convenience: compare LATEST vs the previous suite under --suite-root. "
            "If no explicit compare flags are provided, this is the default behavior."
        ),
    )
    parser.add_argument(
        "--compare-latest-to",
        dest="compare_latest_to",
        default=None,
        help=(
            "(analyze mode, --metric suite_compare) Convenience: compare LATEST vs the given suite_id. "
            "Example: --compare-latest-to 20260101T000000Z"
        ),
    )

    parser.add_argument(
        "--tools",
        help=f"(analyze mode) Comma-separated tools to include (default: {DEFAULT_SCANNERS_CSV})",
    )
    parser.add_argument(
        "--runs-dir",
        default=str(root_dir / "runs"),
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
        "--gt-tolerance",
        type=int,
        default=0,
        help=(
            "(analysis suite) GT scoring line-match tolerance (default: 0). "
            "NOTE: gt_score is intended for benchmark/test suites with ground truth markers/YAML. "
            "This affects only gt_score; it does NOT change location clustering/triage."
        ),
    )
    parser.add_argument(
        "--gt-source",
        choices=["auto", "markers", "yaml", "none"],
        default="auto",
        help=(
            "(analysis suite) GT source selection (default: auto). "
            "NOTE: gt_score is intended for benchmark/test suites (cases with GT markers or gt_catalog.yaml). "
            "auto = markers then YAML if present. "
            "markers = require inline markers like '# DURINN_GT id=a07_01 track=sast set=core owasp=A07'. "
            "yaml = require benchmark/gt_catalog.yaml (copied to <case>/gt/gt_catalog.yaml). "
            "none = skip GT scoring."
        ),
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
