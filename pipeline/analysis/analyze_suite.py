"""pipeline.analysis.analyze_suite

Legacy CLI entrypoint for the analysis suite.

This file remains as a stable command:
  python -m pipeline.analysis.analyze_suite

Internally, it delegates to :mod:`pipeline.analysis.runner`.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

from pipeline.analysis.runner import run_suite

from pipeline.scanners import DEFAULT_SCANNERS, DEFAULT_SCANNERS_CSV


def _parse_tools_csv(raw: str | None) -> List[str]:
    if not raw:
        return []
    items = [t.strip() for t in raw.split(",")]
    return [t for t in items if t]


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the full analysis suite (filesystem artifacts only).")
    ap.add_argument("--repo-name", required=True, help="Repo name as used under runs/<tool>/<repo_name>/...")
    ap.add_argument("--runs-dir", default=str(Path(__file__).resolve().parents[2] / "runs"), help="Base runs directory (default: <repo_root>/runs)")
    ap.add_argument("--out-dir", help="Output directory (default: runs/analysis/<repo-name>/)")
    ap.add_argument("--tools", help=f"Comma-separated tools (default: {DEFAULT_SCANNERS_CSV})")
    ap.add_argument("--tolerance", type=int, default=3, help="Line clustering tolerance (default: 3)")
    ap.add_argument(
        "--gt-tolerance",
        type=int,
        default=0,
        help=(
            "GT scoring line-match tolerance (default: 0). "
            "This affects only gt_score; it does NOT change location clustering/triage."
        ),
    )
    ap.add_argument(
        "--gt-source",
        choices=["auto", "markers", "yaml", "none"],
        default="auto",
        help=(
            "GT source selection (default: auto). "
            "auto = markers then YAML if present; "
            "markers = require inline markers like '# DURINN_GT id=a07_01 track=sast set=core owasp=A07'; "
            "yaml = require benchmark/gt_catalog.yaml (copied to <case>/gt/gt_catalog.yaml); "
            "none = skip GT scoring."
        ),
    )
    ap.add_argument("--mode", choices=["security", "all"], default="security", help="Filtering mode (default: security)")
    ap.add_argument("--formats", default="json,csv", help="Comma-separated formats to write (json,csv)")

    args = ap.parse_args()
    tools = _parse_tools_csv(args.tools) or list(DEFAULT_SCANNERS)
    runs_dir = Path(args.runs_dir)
    out_dir = Path(args.out_dir) if args.out_dir else (runs_dir / "analysis" / args.repo_name)
    formats = [f.strip() for f in str(args.formats).split(",") if f.strip()]

    summary = run_suite(
        repo_name=args.repo_name,
        tools=tools,
        runs_dir=runs_dir,
        out_dir=out_dir,
        tolerance=int(args.tolerance),
        gt_tolerance=int(args.gt_tolerance),
        gt_source=str(args.gt_source),
        mode=args.mode,
        formats=formats,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
