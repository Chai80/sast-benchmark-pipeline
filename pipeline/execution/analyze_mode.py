"""pipeline.execution.analyze_mode

Analysis entrypoint.

This module contains the implementation previously located in
``pipeline.orchestrator.run_analyze``.

Separating analysis from case execution keeps each module focused and prevents
``pipeline/orchestrator.py`` from becoming a large composition root.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from pipeline.suites.layout import resolve_case_dir
from pipeline.models import CaseSpec
from pipeline.scanners import SUPPORTED_SCANNERS


@dataclass(frozen=True)
class AnalyzeRequest:
    metric: str
    case: CaseSpec

    # suite-aware resolution
    suite_root: Path
    suite_id: Optional[str] = None
    case_path: Optional[str] = None

    # legacy analyze
    runs_dir: Optional[Path] = None

    tools: Sequence[str] = ()
    output_format: str = "text"

    out: Optional[str] = None
    analysis_out_dir: Optional[str] = None

    # Analysis / triage knobs
    tolerance: int = 3
    gt_tolerance: int = 0
    gt_source: str = "auto"
    analysis_filter: str = "security"

    # Scope controls
    exclude_prefixes: Sequence[str] = ()
    include_harness: bool = False

    max_unique: int = 25


def _effective_exclude_prefixes(req: AnalyzeRequest, *, is_suite_layout: bool) -> list[str]:
    """Merge CLI-provided prefixes with suite-layout defaults."""
    prefixes: list[str] = [str(p).strip() for p in (req.exclude_prefixes or ()) if str(p).strip()]

    # Default suite-layout noise filter: exclude benchmark harness paths unless explicitly included.
    if is_suite_layout and (not req.include_harness):
        if "benchmark" not in prefixes and "benchmark/" not in prefixes:
            prefixes.append("benchmark")

    return prefixes


def run_analyze(req: AnalyzeRequest) -> int:
    """Run analysis for an existing run set (suite/case aware)."""

    metric = (req.metric or "hotspots").strip()
    if metric not in ("hotspots", "suite"):
        raise SystemExit(f"Invalid metric: {metric}")

    tools = [t for t in req.tools if t in SUPPORTED_SCANNERS]
    if not tools:
        raise SystemExit("No valid tools specified for analyze mode.")

    # Resolve input: case_path overrides suite_id.
    case_dir: Optional[Path] = None
    if req.case_path:
        case_dir = Path(req.case_path).resolve()
    elif req.suite_id:
        case_dir = resolve_case_dir(
            case_id=req.case.case_id,
            suite_id=str(req.suite_id),
            suite_root=req.suite_root,
        )

    if case_dir is not None:
        # v2 layout: tool_runs/ (preferred). v1: scans/ (legacy fallback).
        runs_dir = case_dir / "tool_runs"
        if not runs_dir.exists():
            legacy = case_dir / "scans"
            if legacy.exists():
                runs_dir = legacy
        default_out_dir = case_dir / "analysis"
        is_suite_layout = True
    else:
        if req.runs_dir is None:
            raise SystemExit("Analyze mode requires --suite-id/--case-path OR --runs-dir (legacy).")
        runs_dir = Path(req.runs_dir).resolve()
        default_out_dir = runs_dir / "analysis" / req.case.runs_repo_name
        is_suite_layout = False

    exclude_prefixes = _effective_exclude_prefixes(req, is_suite_layout=is_suite_layout)

    if metric == "suite":
        out_dir = Path(req.analysis_out_dir).resolve() if req.analysis_out_dir else default_out_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        from pipeline.analysis.analyze_suite import run_suite

        summary = run_suite(
            repo_name=req.case.runs_repo_name,
            tools=tools,
            runs_dir=runs_dir,
            out_dir=out_dir,
            tolerance=int(req.tolerance),
            gt_tolerance=int(req.gt_tolerance),
            gt_source=str(req.gt_source),
            mode=str(req.analysis_filter),
            exclude_prefixes=exclude_prefixes,
            include_harness=bool(req.include_harness),
            formats=["json", "csv"],
        )

        print("\n✅ Analysis suite complete")
        print(f"  Repo (runs dir): {req.case.runs_repo_name}")
        print(f"  Tools         : {', '.join(tools)}")
        print(f"  Runs dir      : {runs_dir}")
        print(f"  Output dir    : {out_dir}")
        print(f"  Benchmark pack: {out_dir / 'benchmark_pack.json'}")

        print(json.dumps(summary, indent=2))

        # Best-effort: if this analyze run is happening inside a suite layout,
        # rebuild the suite-level triage_dataset so artifacts stay current.
        if is_suite_layout:
            try:
                from pipeline.analysis.suite_triage_dataset import build_triage_dataset

                # out_dir is the per-case analysis dir: .../runs/suites/<suite_id>/cases/<case_id>/analysis
                suite_dir = out_dir.parent.parent.parent  # .../runs/suites/<suite_id>
                suite_id = suite_dir.name

                ds = build_triage_dataset(suite_dir=str(suite_dir), suite_id=str(suite_id))

                out_csv = ds.get("out_csv") if isinstance(ds, dict) else getattr(ds, "out_csv", None)
                if out_csv:
                    print(f"\n[triage_dataset] wrote: {out_csv}")
            except Exception as e:
                # Never fail analysis due to suite dataset aggregation.
                print(f"\n[triage_dataset] build skipped/failed: {e}")

        return 0

    # metric == hotspots
    out_path = Path(req.out) if req.out else (default_out_dir / "latest_hotspots_by_file.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    from pipeline.analysis.stages.overview import analyze_latest_hotspots_for_repo, print_text_report

    try:
        report = analyze_latest_hotspots_for_repo(
            repo_name=req.case.runs_repo_name,
            tools=list(tools),
            runs_dir=runs_dir,
            mode=str(req.analysis_filter),
            exclude_prefixes=exclude_prefixes,
        )
    except FileNotFoundError as e:
        print("\n⚠️  No normalized runs found for analysis.")
        print("   Expected layout:")
        print("     v2: <runs_dir>/<tool>/<run_id>/normalized.json")
        print("     v1: <runs_dir>/<tool>/<repo_name>/<run_id>/<repo_name>.normalized.json")
        print(f"   runs_dir       : {runs_dir}")
        print(f"   repo_name      : {req.case.runs_repo_name}")
        print(f"   tools          : {', '.join(tools)}")
        print(f"\n   Details: {e}")
        return 1

    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n📊 Hotspots-by-file report")
    print(f"  Repo (runs dir): {req.case.runs_repo_name}")
    print(f"  Tools         : {', '.join(tools)}")
    print(f"  Runs dir      : {runs_dir}")
    print(f"  Saved report  : {out_path}")

    if req.output_format == "json":
        print(json.dumps(report, indent=2))
    else:
        print_text_report(report, max_unique=int(req.max_unique))

    return 0
