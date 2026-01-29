"""CLI entrypoint for analytics mart exports.

Usage
-----
python -m pipeline.analysis.analytics_mart --suite-dir runs/suites/<suite_id>
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import write_analytics_mart


def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Export AnalyticsMart star schema tables for a suite.")
    ap.add_argument(
        "--suite-dir",
        required=True,
        help="Path to runs/suites/<suite_id>.",
    )
    ap.add_argument(
        "--suite-id",
        default=None,
        help="Optional suite_run_id override (defaults to suite_dir name).",
    )
    ap.add_argument(
        "--out-dirname",
        default="AnalyticsMart",
        help="Folder name under the suite root. Default: AnalyticsMart",
    )
    return ap.parse_args()


def main() -> None:
    args = _parse_args()
    res = write_analytics_mart(
        suite_dir=Path(args.suite_dir),
        suite_id=args.suite_id,
        out_dirname=str(args.out_dirname),
    )
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
