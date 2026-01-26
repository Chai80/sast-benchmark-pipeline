from __future__ import annotations

"""cli.commands.compare_suites

Suite-to-suite comparison command.

This is an *analysis-only* operation: it compares already-generated suite
artifacts and writes a deterministic diff report under
runs/suites/<suite_out>/analysis/_tables.

This command is intentionally CLI-level (does not go through pipeline.analyze)
so it stays lightweight and does not require specifying tools.
"""

from pathlib import Path
from typing import Optional, Tuple

from cli.utils.suite_picker import resolve_suite_dir_ref
from pipeline.analysis.suite.suite_compare_report import build_suite_compare_report


def _parse_compare_suites_csv(raw: str) -> Tuple[str, str]:
    s = str(raw or "").strip()
    if not s:
        raise SystemExit(
            "--compare-suites requires a value like 'latest,previous' or '<suiteA>,<suiteB>'"
        )

    parts = [p.strip() for p in s.split(",") if p.strip()]
    if len(parts) != 2:
        raise SystemExit(
            f"--compare-suites expects exactly two comma-separated refs (got: {raw!r})"
        )
    return parts[0], parts[1]


def _resolve_pair(
    *,
    suite_root: Path,
    ref_a: str,
    ref_b: str,
) -> Tuple[Path, Path]:
    suite_root = suite_root.resolve()

    a = resolve_suite_dir_ref(suite_root, ref_a)
    if a is None:
        raise SystemExit(f"Could not resolve suite ref A={ref_a!r} under {suite_root}")

    b = resolve_suite_dir_ref(suite_root, ref_b)
    if b is None:
        raise SystemExit(f"Could not resolve suite ref B={ref_b!r} under {suite_root}")

    return a, b


def run_suite_compare(args, *, suite_root: Path) -> int:
    """Run suite compare report.

    Selection precedence (most explicit wins):
      1) --compare-suites A,B
      2) --compare-latest-to <suite_id>
      3) --compare-latest-previous
      4) default: latest vs previous
    """

    suite_root = Path(suite_root).expanduser().resolve()

    ref_a: Optional[str] = None
    ref_b: Optional[str] = None

    if getattr(args, "compare_suites", None):
        ref_a, ref_b = _parse_compare_suites_csv(str(args.compare_suites))
    elif getattr(args, "compare_latest_to", None):
        ref_a, ref_b = "latest", str(args.compare_latest_to)
    elif bool(getattr(args, "compare_latest_previous", False)):
        ref_a, ref_b = "latest", "previous"
    else:
        # Default: non-interactive drift check.
        ref_a, ref_b = "latest", "previous"

    suite_a, suite_b = _resolve_pair(
        suite_root=suite_root, ref_a=str(ref_a), ref_b=str(ref_b)
    )

    # Default output: write into suite A (usually 'latest').
    summary = build_suite_compare_report(suite_dir_a=suite_a, suite_dir_b=suite_b)

    print("\n✅ Suite compare report")
    print(f"  suite_a : {suite_a.name} ({suite_a})")
    print(f"  suite_b : {suite_b.name} ({suite_b})")
    print(f"  out_csv : {summary.get('out_csv')}")
    print(f"  out_json: {summary.get('out_json')}")

    alerts = summary.get("alerts") if isinstance(summary, dict) else None
    if alerts:
        print("\nAlerts:")
        for a in alerts:
            print(f"  - {a}")

    return 0
