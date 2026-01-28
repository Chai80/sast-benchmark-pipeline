"""pipeline.analysis.suite.triage_calibration_build

Suite-level triage calibration builder.

The original implementation lived in
:mod:`pipeline.analysis.suite.suite_triage_calibration` and grew large. The
core build logic now lives here, while the public module keeps a small facade
for backwards compatibility.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from pipeline.analysis.io.write_artifacts import write_csv, write_json

from .triage_calibration_counts import _accumulate_calibration_counts, _partition_cases_by_gt
from .triage_calibration_io import _load_csv_rows
from .triage_calibration_log import _write_best_effort_calibration_log
from .triage_calibration_stats import (
    _build_suspicious_cases,
    _build_tool_stats_by_owasp,
    _compute_tool_stats,
    _flatten_report_by_owasp_rows,
)
from .triage_calibration_types import (
    TRIAGE_CALIBRATION_SCHEMA_VERSION,
    CalibrationParamsV1,
)
from .triage_calibration_utils import _now_iso


def build_triage_calibration(
    *,
    suite_dir: Path,
    suite_id: Optional[str] = None,
    params: Optional[CalibrationParamsV1] = None,
    dataset_relpath: str = "analysis/_tables/triage_dataset.csv",
    out_dirname: str = "analysis",
    write_report_csv: bool = True,
) -> Dict[str, Any]:
    """Build suite-level triage calibration JSON.

    Returns a JSON-serializable summary dict (also written to disk).
    """

    suite_dir = Path(suite_dir).resolve()
    if not suite_dir.exists() or not suite_dir.is_dir():
        raise FileNotFoundError(f"suite_dir not found: {suite_dir}")

    sid = str(suite_id) if suite_id else suite_dir.name
    params = params or CalibrationParamsV1()

    dataset_csv = suite_dir / dataset_relpath
    if not dataset_csv.exists():
        raise FileNotFoundError(f"triage_dataset.csv not found: {dataset_csv}")

    rows = _load_csv_rows(dataset_csv)

    # Determine which cases have GT artifacts.
    case_ids = sorted(
        {str(r.get("case_id") or "").strip() for r in rows if str(r.get("case_id") or "").strip()}
    )
    included_cases, excluded_cases_no_gt, included_set = _partition_cases_by_gt(
        suite_dir=suite_dir, case_ids=case_ids
    )

    counts = _accumulate_calibration_counts(rows=rows, included_set=included_set)

    suspicious_cases = _build_suspicious_cases(
        included_cases=included_cases,
        per_case_clusters=counts.per_case_clusters,
        per_case_overlap_sum=counts.per_case_overlap_sum,
    )

    tool_stats_global = _compute_tool_stats(tp=counts.tp, fp=counts.fp, params=params)

    tool_stats_by_owasp = _build_tool_stats_by_owasp(
        params=params,
        tp_by_owasp=counts.tp_by_owasp,
        fp_by_owasp=counts.fp_by_owasp,
        support_clusters_by_owasp=counts.support_clusters_by_owasp,
        support_cases_by_owasp=counts.support_cases_by_owasp,
        overlap_sum_by_owasp=counts.overlap_sum_by_owasp,
    )

    report_by_owasp_rows = _flatten_report_by_owasp_rows(
        tool_stats_by_owasp=tool_stats_by_owasp, params=params
    )

    out_dir = suite_dir / out_dirname
    out_json = out_dir / "triage_calibration.json"
    out_report = out_dir / "_tables" / "triage_calibration_report.csv"
    out_report_by_owasp = out_dir / "_tables" / "triage_calibration_report_by_owasp.csv"
    out_log = out_dir / "triage_calibration.log"

    generated_at = _now_iso()

    payload: Dict[str, Any] = {
        "schema_version": TRIAGE_CALIBRATION_SCHEMA_VERSION,
        "suite_id": sid,
        "generated_at": generated_at,
        "input_dataset": str(dataset_csv.relative_to(suite_dir)).replace("\\", "/"),
        "alpha": float(params.alpha),
        "beta": float(params.beta),
        "p_clamp": {"min": float(params.p_min), "max": float(params.p_max)},
        "included_cases": list(included_cases),
        "excluded_cases_no_gt": list(excluded_cases_no_gt),
        "suspicious_cases": list(suspicious_cases),
        "tool_stats_global": list(tool_stats_global),
        # Backwards compatible alias for v1 consumers/tests that still read `tool_stats`.
        # Keep this during the v1->v2 transition so older tooling continues to work.
        "tool_stats": list(tool_stats_global),
        "tool_stats_by_owasp": tool_stats_by_owasp,
        "scoring": {
            "strategy": "triage_score_v1",
            "agreement_lambda": float(params.agreement_lambda),
            "severity_bonus": dict(params.severity_bonus),
            "min_support_by_owasp": int(params.min_support_by_owasp),
        },
    }

    # Deterministic JSON ordering is achieved by:
    # - stable list ordering (sorted tools/cases)
    # - dict insertion order defined above
    write_json(out_json, payload, indent=2)

    if write_report_csv:
        write_csv(
            out_report,
            tool_stats_global,
            fieldnames=["tool", "tp", "fp", "p_smoothed", "weight"],
        )

        write_csv(
            out_report_by_owasp,
            report_by_owasp_rows,
            fieldnames=[
                "owasp_id",
                "tool",
                "tp",
                "fp",
                "p_smoothed",
                "weight",
                "support_clusters",
                "support_cases",
                "gt_positive_clusters",
                "min_support_by_owasp",
                "fallback_to_global",
            ],
        )

    _write_best_effort_calibration_log(
        out_log=out_log,
        sid=sid,
        dataset_csv=dataset_csv,
        out_json=out_json,
        included_cases=included_cases,
        excluded_cases_no_gt=excluded_cases_no_gt,
        tool_stats_global=tool_stats_global,
        suspicious_cases=suspicious_cases,
        generated_at=generated_at,
    )

    return {
        "suite_id": sid,
        "suite_dir": str(suite_dir),
        "dataset_csv": str(dataset_csv),
        "out_json": str(out_json),
        "out_report_csv": str(out_report) if write_report_csv else "",
        "out_report_by_owasp_csv": str(out_report_by_owasp) if write_report_csv else "",
        "included_cases": list(included_cases),
        "excluded_cases_no_gt": list(excluded_cases_no_gt),
        "suspicious_cases": list(suspicious_cases),
        "tools": int(len(tool_stats_global)),
        "owasp_slices": int(len(tool_stats_by_owasp)),
        "built_at": payload.get("generated_at"),
    }


__all__ = [
    "build_triage_calibration",
]
