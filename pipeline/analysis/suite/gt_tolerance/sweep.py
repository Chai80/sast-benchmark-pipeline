"""pipeline.analysis.suite.gt_tolerance.sweep

Deterministic GT tolerance sweep orchestration.

The public facade remains :mod:`pipeline.analysis.suite.gt_tolerance_sweep`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from pipeline.analysis.io.write_artifacts import write_csv, write_json
from pipeline.analysis.suite.suite_triage_calibration import tool_weights_from_calibration
from pipeline.orchestrator import AnalyzeRequest
from pipeline.pipeline import SASTBenchmarkPipeline
from pipeline.suites.bundles import safe_name

from .metrics import (
    DEFAULT_GT_TOLERANCE_CANDIDATES,
    _compute_dataset_overlap_stats,
    _extract_macro_metrics,
    _read_csv_rows,
    _safe_float,
    _safe_int,
    ambiguity_warnings_from_overlap_stats,
    parse_gt_tolerance_candidates,
)
from .snapshot import _snapshot_suite_analysis, disable_suite_calibration

def run_gt_tolerance_sweep(
    *,
    pipeline: SASTBenchmarkPipeline,
    suite_root: Path,
    suite_id: str,
    suite_dir: Path,
    cases: Sequence[Any],
    tools: Sequence[str],
    tolerance: int,
    gt_source: str,
    analysis_filter: str,
    exclude_prefixes: Sequence[str],
    include_harness: bool,
    candidates: Sequence[int],
    out_dirname: str = "analysis",
) -> Dict[str, Any]:
    """Run a deterministic sweep of gt_tolerance values.

    This function *mutates* the suite-level analysis outputs while it runs.
    Always rely on the snapshots/report for comparisons.

    Returns
    -------
    Dict[str, Any]
        JSON-serializable payload including flattened rows and output paths.
    """

    from pipeline.analysis.suite.suite_triage_dataset import build_triage_dataset
    from pipeline.analysis.suite.suite_triage_calibration import (
        build_triage_calibration,
    )
    from pipeline.analysis.suite.suite_triage_eval import build_triage_eval

    suite_dir = Path(suite_dir).resolve()
    analysis_dir = suite_dir / out_dirname
    tables_dir = analysis_dir / "_tables"
    sweeps_dir = analysis_dir / "_sweeps"

    tables_dir.mkdir(parents=True, exist_ok=True)
    sweeps_dir.mkdir(parents=True, exist_ok=True)

    # Normalize candidates deterministically.
    cand_list = [int(x) for x in candidates if int(x) >= 0]
    if not cand_list:
        cand_list = list(DEFAULT_GT_TOLERANCE_CANDIDATES)

    # stable order
    cand_list = sorted(set(cand_list))

    rows_out: List[Dict[str, Any]] = []
    tool_rows_out: List[Dict[str, Any]] = []
    snapshots: List[Dict[str, Any]] = []

    for t in cand_list:
        print("\n" + "=" * 72)
        print(f"🔍 GT tolerance sweep: gt_tolerance={t}")

        # Ensure per-case analysis doesn't pick up an old calibration.
        disable_suite_calibration(suite_dir, out_dirname=out_dirname)

        # Re-analyze all cases with the candidate tolerance.
        rc_overall = 0
        for idx, case in enumerate(cases, start=1):
            case_id = str(getattr(case, "case_id", "") or "").strip() or "unknown"
            print("\n" + "-" * 72)
            print(f"🔁 Analyze sweep {idx}/{len(cases)}: {case_id} (gt_tolerance={t})")

            case_dir = (suite_dir / "cases" / safe_name(case_id)).resolve()

            try:
                areq = AnalyzeRequest(
                    metric="suite",
                    case=case,
                    suite_root=Path(suite_root),
                    suite_id=str(suite_id),
                    case_path=str(case_dir),
                    tools=tuple(tools),
                    tolerance=int(tolerance),
                    gt_tolerance=int(t),
                    gt_source=str(gt_source),
                    analysis_filter=str(analysis_filter),
                    exclude_prefixes=tuple(exclude_prefixes or ()),
                    include_harness=bool(include_harness),
                    skip_suite_aggregate=True,
                )
                rc = int(pipeline.analyze(areq))
            except Exception as e:
                print(f"  ❌ analyze failed for {case_id} @ gt_tolerance={t}: {e}")
                rc = 2

            rc_overall = max(rc_overall, rc)

        # Build suite-level artifacts for THIS tolerance.
        ds = build_triage_dataset(suite_dir=suite_dir, suite_id=str(suite_id))
        build_triage_calibration(suite_dir=suite_dir, suite_id=str(suite_id))
        ev = build_triage_eval(
            suite_dir=suite_dir, suite_id=str(suite_id), include_tool_marginal=False
        )

        dataset_csv = Path(
            str(ds.get("out_csv") or (analysis_dir / "_tables" / "triage_dataset.csv"))
        ).resolve()

        stats = _compute_dataset_overlap_stats(dataset_csv)

        # Ambiguity warnings (many-to-one / one-to-many). Keep both counts and
        # human-readable warnings in the sweep outputs so CI/users can spot
        # tolerance-induced matching ambiguity.
        amb_warnings = ambiguity_warnings_from_overlap_stats(stats)

        # Tool stats (for a separate tool-stats table)
        cal_json_path = analysis_dir / "triage_calibration.json"
        cal_obj: Dict[str, Any] = {}
        if cal_json_path.exists():
            try:
                cal_obj = json.loads(cal_json_path.read_text(encoding="utf-8"))
            except Exception:
                cal_obj = {}

        weights = tool_weights_from_calibration(cal_obj)

        report_csv_path = analysis_dir / "_tables" / "triage_calibration_report.csv"
        if report_csv_path.exists():
            try:
                for r in _read_csv_rows(report_csv_path):
                    tool = str(r.get("tool") or "").strip()
                    if not tool:
                        continue
                    tool_rows_out.append(
                        {
                            "gt_tolerance": int(t),
                            "tool": tool,
                            "tp": _safe_int(r.get("tp"), 0),
                            "fp": _safe_int(r.get("fp"), 0),
                            "p_smoothed": _safe_float(r.get("p_smoothed"), 0.0),
                            "weight": _safe_float(r.get("weight"), float(weights.get(tool, 0.0))),
                        }
                    )
            except Exception:
                # Best-effort
                pass
        else:
            # Fallback to JSON-only weights (no tp/fp details).
            for tool, w in sorted(weights.items()):
                tool_rows_out.append(
                    {
                        "gt_tolerance": int(t),
                        "tool": str(tool),
                        "tp": "",
                        "fp": "",
                        "p_smoothed": "",
                        "weight": float(w),
                    }
                )

        # Eval metrics (macro flatten)
        metrics = _extract_macro_metrics(ev)

        # Snapshot suite-level artifacts
        snap_dir = sweeps_dir / f"gt_tol_{int(t)}"
        _snapshot_suite_analysis(
            suite_dir=suite_dir, snapshot_dir=snap_dir, out_dirname=out_dirname
        )
        snapshots.append({"gt_tolerance": int(t), "snapshot_dir": str(snap_dir)})

        row: Dict[str, Any] = {
            "gt_tolerance": int(t),
            "analysis_rc": int(rc_overall),
            "clusters_total": int(stats.clusters_total),
            "gt_overlap_1": int(stats.gt_overlap_1),
            "gt_overlap_0": int(stats.gt_overlap_0),
            "gt_overlap_rate": float(stats.gt_overlap_rate),
            "gt_ids_covered": int(stats.gt_ids_covered),
            # Explicit ambiguity fields (aliases make the meaning obvious).
            # - many_to_one: a single cluster overlaps multiple GT IDs
            # - one_to_many: a single GT ID overlaps multiple clusters
            "many_to_one_clusters": int(stats.clusters_multi_gt),
            "one_to_many_gt_ids": int(stats.gt_ids_multi_cluster),
            "clusters_multi_gt": int(stats.clusters_multi_gt),
            "gt_ids_multi_cluster": int(stats.gt_ids_multi_cluster),
            "max_clusters_per_gt_id": int(stats.max_clusters_per_gt_id),
            "max_gt_ids_per_cluster": int(stats.max_gt_ids_per_cluster),
            # Warning summary (stable strings, safe to parse).
            "gt_ambiguity_warning": 1 if amb_warnings else 0,
            "gt_ambiguity_warning_count": int(len(amb_warnings)),
            "gt_ambiguity_warnings_json": json.dumps(amb_warnings, ensure_ascii=False),
            "snapshot_dir": str(snap_dir),
        }
        row.update(metrics)

        rows_out.append(row)

        print("\n📊 Sweep row")
        print(
            f"  gt_tolerance={t} clusters={stats.clusters_total} gt_overlap_1={stats.gt_overlap_1} "
            f"multi_gt_clusters={stats.clusters_multi_gt} gt_ids_multi_cluster={stats.gt_ids_multi_cluster}"
        )

    # Stable sort by gt_tolerance
    rows_out.sort(key=lambda r: int(r.get("gt_tolerance", 0)))
    tool_rows_out.sort(key=lambda r: (int(r.get("gt_tolerance", 0)), str(r.get("tool") or "")))

    out_report_csv = tables_dir / "gt_tolerance_sweep_report.csv"
    out_tool_csv = tables_dir / "gt_tolerance_sweep_tool_stats.csv"
    out_json = analysis_dir / "gt_tolerance_sweep.json"

    write_csv(out_report_csv, rows_out)
    write_csv(
        out_tool_csv,
        tool_rows_out,
        fieldnames=["gt_tolerance", "tool", "tp", "fp", "p_smoothed", "weight"],
    )

    payload: Dict[str, Any] = {
        "schema_version": "gt_tolerance_sweep_v1",
        "suite_id": str(suite_id),
        "suite_dir": str(suite_dir),
        "candidates": list(cand_list),
        "out_report_csv": str(out_report_csv),
        "out_tool_csv": str(out_tool_csv),
        "snapshots": list(snapshots),
        "rows": list(rows_out),
    }

    write_json(out_json, payload, indent=2)

    print("\n✅ GT tolerance sweep report")
    print(f"  Report : {out_report_csv}")
    print(f"  Tools  : {out_tool_csv}")
    print(f"  JSON   : {out_json}")

    return payload


