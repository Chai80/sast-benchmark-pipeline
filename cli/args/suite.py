from __future__ import annotations

import argparse


def add_suite_args(parser: argparse.ArgumentParser) -> None:
    """Register CLI flags primarily used by suite mode.

    These flags are safe to register globally because argparse has a single
    parser for all modes; we rely on mode-specific handler logic to interpret
    them.
    """

    parser.add_argument(
        "--suite-file",
        dest="suite_file",
        help=(
            "(suite mode) Optional Python *replay file* (.py exporting SUITE_DEF or SUITE_RAW). "
            "Think of this as a replay button for an interactively curated suite (usually saved under runs/suites/<suite_id>/replay/). "
            "If omitted, you can build a suite interactively "
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
        "--branches",
        dest="branches",
        default=None,
        help=(
            "(suite mode) When used with --repo-url, bootstrap a git worktrees root containing these branches. "
            "Comma-separated; supports OWASP-ish ranges like 'A01-A10'. "
            "Example: --repo-url https://... --branches A03,A07"
        ),
    )

    parser.add_argument(
        "--max-cases",
        dest="max_cases",
        type=int,
        default=None,
        help="(suite mode) When loading cases from --cases-from/--worktrees-root, only include the first N cases.",
    )

    # QA runbook: triage calibration (suite mode)
    parser.add_argument(
        "--qa-calibration",
        dest="qa_calibration",
        action="store_true",
        help=(
            "(suite mode) Run the triage-calibration QA runbook: run suite, build calibration artifacts, "
            "re-run analysis so per-case triage_queue includes populated triage_score_v1, then validate outputs."
        ),
    )
    parser.add_argument(
        "--qa-scope",
        dest="qa_scope",
        choices=["smoke", "full"],
        default="smoke",
        help=(
            "(suite mode, --qa-calibration) Which default OWASP set to run: "
            "smoke=A03+A07, full=A01..A10. Overridden by --qa-owasp or --qa-cases."
        ),
    )
    parser.add_argument(
        "--qa-owasp",
        dest="qa_owasp",
        default=None,
        help=(
            "(suite mode, --qa-calibration) Override OWASP selection, e.g. 'A03,A07' or 'A01-A10'. "
            "If provided, this filters cases by OWASP id when the suite is OWASP-structured."
        ),
    )
    parser.add_argument(
        "--qa-cases",
        dest="qa_cases",
        default=None,
        help=(
            "(suite mode, --qa-calibration) Optional case selectors to include (comma-separated). "
            "Each selector is treated as a substring/glob matched against case_id/branch/label. "
            "If provided, overrides --qa-scope/--qa-owasp and works for non-OWASP suites too."
        ),
    )
    parser.add_argument(
        "--qa-no-reanalyze",
        dest="qa_no_reanalyze",
        action="store_true",
        help=(
            "(suite mode, --qa-calibration) Skip the extra analyze pass that recomputes per-case triage_queue.csv "
            "using the newly built suite calibration. Useful for debugging."
        ),
    )

    parser.add_argument(
        "--gt-tolerance-sweep",
        default=None,
        help=(
            "(suite qa-calibration) Deterministically sweep multiple GT tolerances and write a comparison report. "
            "Value is a comma-separated list of ints, e.g. '0,1,2,3,5,10'. "
            "Writes runs/suites/<suite_id>/analysis/_tables/gt_tolerance_sweep_report.csv and snapshots under "
            "runs/suites/<suite_id>/analysis/_sweeps/gt_tol_<t>/."
        ),
    )
    parser.add_argument(
        "--gt-tolerance-auto",
        action="store_true",
        help=(
            "(suite qa-calibration) Pick a GT tolerance deterministically (no prompts). "
            "Uses --gt-tolerance-sweep candidates when provided; otherwise defaults to '0,1,2,3,5,10'."
        ),
    )
    parser.add_argument(
        "--gt-tolerance-auto-min-fraction",
        type=float,
        default=0.95,
        help=(
            "(suite qa-calibration) Auto selection rule: choose the smallest tolerance achieving >= this fraction of "
            "the maximum GT-positive clusters observed in the sweep (default: 0.95)."
        ),
    )
