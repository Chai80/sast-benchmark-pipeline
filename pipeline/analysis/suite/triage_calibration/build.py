"""pipeline.analysis.suite.triage_calibration.build

Suite-level triage calibration builder.

This is the only module in the calibration implementation that performs
filesystem writes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from pipeline.analysis.io.write_artifacts import write_csv, write_json, write_text

from .compute import (
    _accumulate_calibration_counts,
    _build_suspicious_cases,
    _build_tool_stats_by_owasp,
    _compute_tool_stats,
    _flatten_report_by_owasp_rows,
    _partition_cases_by_gt,
)
from .core import (
    TRIAGE_CALIBRATION_SCHEMA_VERSION,
    CalibrationParamsV1,
    _load_csv_rows,
    _now_iso,
)


def _write_best_effort_calibration_log(
    *,
    out_log: Path,
    sid: str,
    dataset_csv: Path,
    out_json: Path,
    included_cases: Sequence[str],
    excluded_cases_no_gt: Sequence[str],
    tool_stats_global: Sequence[Mapping[str, Any]],
    suspicious_cases: Sequence[Mapping[str, Any]],
    generated_at: str,
) -> None:
    """Best-effort log: surface suspicious cases explicitly."""

    try:
        lines: List[str] = []
        lines.append(f"[{generated_at}] triage_calibration build")
        lines.append(f"suite_id              : {sid}")
        lines.append(f"dataset_csv           : {dataset_csv}")
        lines.append(f"included_cases        : {len(list(included_cases))}")
        lines.append(f"excluded_cases_no_gt  : {len(list(excluded_cases_no_gt))}")
        lines.append(f"tools                 : {len(list(tool_stats_global))}")
        lines.append(f"out_json              : {out_json}")
        if suspicious_cases:
            lines.append("")
            lines.append(f"suspicious_cases ({len(list(suspicious_cases))}):")
            for sc in suspicious_cases:
                lines.append(
                    f"  - {sc.get('case_id')}: clusters={sc.get('cluster_count')} overlap_sum={sc.get('gt_overlap_sum')}"
                )
        write_text(out_log, "\n".join(lines) + "\n")
    except Exception:
        # Best-effort by design: never crash the pipeline for log output.
        pass


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
        "tool_stats": list(tool_stats_global),
        "tool_stats_by_owasp": tool_stats_by_owasp,
        "scoring": {
            "strategy": "triage_score_v1",
            "agreement_lambda": float(params.agreement_lambda),
            "severity_bonus": dict(params.severity_bonus),
            "min_support_by_owasp": int(params.min_support_by_owasp),
        },
    }

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
