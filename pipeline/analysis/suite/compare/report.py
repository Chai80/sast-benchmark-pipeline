"""pipeline.analysis.suite.compare.report

Suite-to-suite drift comparison report.

This module is the implementation split from
``pipeline.analysis.suite.suite_compare_report``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from pipeline.analysis.io.write_artifacts import write_csv, write_json

from .diff import _to_int
from .load import (
    _dataset_counts,
    _extract_eval,
    _extract_gt_policy,
    _load_calibration_weights,
    _load_suite_artifacts,
    _load_tool_marginal,
    _load_tool_utility,
)
from .model import SuiteArtifacts
from .report_sections import (
    _append_calibration_by_owasp,
    _append_calibration_global,
    _append_dataset_counts,
    _append_eval_diff,
    _append_policy_diff,
    _append_row,
    _append_scanner_config_diff,
    _append_tool_marginal_diff,
    _append_tool_utility_diff,
)


SUITE_COMPARE_REPORT_SCHEMA_V1 = "suite_compare_report_v1"


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _build_alerts(
    *,
    a: SuiteArtifacts,
    b: SuiteArtifacts,
    pol_a: Mapping[str, Any],
    pol_b: Mapping[str, Any],
    warn_a: Sequence[str],
    warn_b: Sequence[str],
) -> List[str]:
    alerts: List[str] = []

    def _pol_get(pol: Mapping[str, Any], path: Sequence[str]) -> Any:
        cur: Any = pol
        for key in path:
            if not isinstance(cur, Mapping):
                return None
            cur = cur.get(key)
        return cur

    try:
        eff_a = _pol_get(pol_a, ("effective_gt_tolerance",))
        eff_b = _pol_get(pol_b, ("effective_gt_tolerance",))
        if _to_int(eff_a, 0) != _to_int(eff_b, 0):
            alerts.append(f"GT tolerance changed: {eff_a} -> {eff_b}")
    except Exception:
        pass

    # Scanner profile/config drift (a common explanation for "tool drift").
    try:
        prof_a = (a.scanner_config or {}).get("profile")
        prof_b = (b.scanner_config or {}).get("profile")
        if prof_a and prof_b and str(prof_a) != str(prof_b):
            alerts.append(f"Scanner profile changed: {prof_a} -> {prof_b}")
    except Exception:
        pass

    try:
        hashes_a = (
            a.scanner_config.get("config_receipt_hashes")
            if isinstance(a.scanner_config, Mapping)
            else {}
        )
        hashes_b = (
            b.scanner_config.get("config_receipt_hashes")
            if isinstance(b.scanner_config, Mapping)
            else {}
        )
        if isinstance(hashes_a, Mapping) and isinstance(hashes_b, Mapping):
            changed_tools: List[str] = []
            for t in sorted(set(list(hashes_a.keys()) + list(hashes_b.keys()))):
                if json.dumps(hashes_a.get(t) or [], sort_keys=True) != json.dumps(
                    hashes_b.get(t) or [], sort_keys=True
                ):
                    changed_tools.append(str(t))
            if changed_tools:
                alerts.append(f"Scanner config signature changed for tools: {changed_tools}")
    except Exception:
        pass

    if warn_a:
        alerts.append(f"Suite A warnings: {', '.join(sorted(set(warn_a)))}")
    if warn_b:
        alerts.append(f"Suite B warnings: {', '.join(sorted(set(warn_b)))}")
    return alerts


def _append_alert_rows(rows: List[Dict[str, Any]], *, alerts: Sequence[str]) -> None:
    for msg in alerts:
        _append_row(
            rows,
            section="alerts",
            name="alert",
            a_val="",
            b_val="",
            delta_val=None,
            notes=str(msg),
        )


_SECTION_ORDER: Dict[str, float] = {
    "policy": 0,
    "scanner_config": 0.5,
    "dataset": 1,
    "eval_micro": 2,
    "eval_macro": 3,
    "calibration_weight_global": 4,
    "calibration_weight_by_owasp": 5,
    "tool_utility": 6,
    "tool_marginal": 7,
    "alerts": 99,
}


def _row_key(r: Mapping[str, Any]) -> Tuple[float, str, str, str, int]:
    sec = str(r.get("section") or "")
    name = str(r.get("name") or "")
    tool = str(r.get("tool") or "")
    strat = str(r.get("strategy") or "")
    k = _to_int(r.get("k"), 0)
    return (
        float(_SECTION_ORDER.get(sec, 50.0)),
        sec,
        name + ":" + tool + ":" + strat,
        str(tool) + str(strat),
        int(k),
    )


def _suite_ref(a: SuiteArtifacts) -> Dict[str, Any]:
    return {
        "suite_id": a.suite_id,
        "suite_dir": str(a.suite_dir),
        "suite_json_path": str(a.suite_json_path),
        "qa_manifest_path": "" if a.qa_manifest_path is None else str(a.qa_manifest_path),
        "eval_summary_path": "" if a.eval_summary_path is None else str(a.eval_summary_path),
        "dataset_csv": "" if a.dataset_csv is None else str(a.dataset_csv),
        "tool_utility_csv": "" if a.tool_utility_csv is None else str(a.tool_utility_csv),
        "calibration_json": "" if a.calibration_json is None else str(a.calibration_json),
        "tool_marginal_csv": "" if a.tool_marginal_csv is None else str(a.tool_marginal_csv),
    }


def build_suite_compare_report(
    *,
    suite_dir_a: str | Path,
    suite_dir_b: str | Path,
    out_suite_dir: Optional[str | Path] = None,
    out_basename: str = "suite_compare_report",
    include_tool_marginal: bool = True,
) -> Dict[str, Any]:
    """Compare two suite dirs and write a drift report."""

    a_dir = Path(suite_dir_a).resolve()
    b_dir = Path(suite_dir_b).resolve()

    out_dir = Path(out_suite_dir).resolve() if out_suite_dir else a_dir
    out_tables = out_dir / "analysis" / "_tables"

    a, warn_a = _load_suite_artifacts(a_dir)
    b, warn_b = _load_suite_artifacts(b_dir)

    if a.eval_summary is None or b.eval_summary is None:
        missing = []
        if a.eval_summary is None:
            missing.append(f"{a.suite_id}: triage_eval_summary.json")
        if b.eval_summary is None:
            missing.append(f"{b.suite_id}: triage_eval_summary.json")
        raise SystemExit("Cannot compare suites; missing required eval summary: " + ", ".join(missing))

    pol_a = _extract_gt_policy(a.qa_manifest)
    pol_b = _extract_gt_policy(b.qa_manifest)

    eval_a = _extract_eval(a.eval_summary)
    eval_b = _extract_eval(b.eval_summary)

    ds_a = _dataset_counts(a.dataset_csv)
    ds_b = _dataset_counts(b.dataset_csv)

    cal_w_a, cal_by_owasp_a = _load_calibration_weights(a.calibration_json)
    cal_w_b, cal_by_owasp_b = _load_calibration_weights(b.calibration_json)

    util_a = _load_tool_utility(a.tool_utility_csv)
    util_b = _load_tool_utility(b.tool_utility_csv)

    marg_a = _load_tool_marginal(a.tool_marginal_csv) if include_tool_marginal else {}
    marg_b = _load_tool_marginal(b.tool_marginal_csv) if include_tool_marginal else {}

    rows_csv: List[Dict[str, Any]] = []
    _append_policy_diff(rows_csv, pol_a=pol_a, pol_b=pol_b)

    sc_a = a.scanner_config if isinstance(a.scanner_config, Mapping) else {}
    sc_b = b.scanner_config if isinstance(b.scanner_config, Mapping) else {}
    _append_scanner_config_diff(rows_csv, sc_a=sc_a, sc_b=sc_b)

    _append_dataset_counts(rows_csv, ds_a=ds_a, ds_b=ds_b)
    _append_eval_diff(rows_csv, eval_a=eval_a, eval_b=eval_b)
    _append_calibration_global(rows_csv, cal_w_a=cal_w_a, cal_w_b=cal_w_b)
    _append_calibration_by_owasp(rows_csv, cal_by_owasp_a=cal_by_owasp_a, cal_by_owasp_b=cal_by_owasp_b)
    _append_tool_utility_diff(rows_csv, util_a=util_a, util_b=util_b)

    if include_tool_marginal and marg_a and marg_b:
        _append_tool_marginal_diff(rows_csv, marg_a=marg_a, marg_b=marg_b)

    alerts = _build_alerts(a=a, b=b, pol_a=pol_a, pol_b=pol_b, warn_a=warn_a, warn_b=warn_b)
    _append_alert_rows(rows_csv, alerts=alerts)
    rows_csv.sort(key=_row_key)

    out_json = out_tables / f"{out_basename}.json"
    out_csv = out_tables / f"{out_basename}.csv"

    report: Dict[str, Any] = {
        "schema_version": SUITE_COMPARE_REPORT_SCHEMA_V1,
        "generated_at": _now_iso_utc(),
        "suite_a": _suite_ref(a),
        "suite_b": _suite_ref(b),
        "warnings": {"suite_a": list(sorted(set(warn_a))), "suite_b": list(sorted(set(warn_b)))},
        "alerts": list(alerts),
        "diff": {
            "gt_tolerance_policy": {"a": pol_a, "b": pol_b},
            "scanner_config": {"a": a.scanner_config, "b": b.scanner_config},
            "dataset_counts": {"a": ds_a, "b": ds_b},
            "calibration_weights_global": {"a": cal_w_a, "b": cal_w_b},
            "tool_utility": {"a": util_a, "b": util_b},
        },
        "out_csv": str(out_csv),
        "out_json": str(out_json),
    }

    write_json(out_json, report)
    write_csv(out_csv, rows_csv, fieldnames=["section", "name", "tool", "strategy", "k", "a", "b", "delta", "notes"])

    return {
        "suite_a": a.suite_id,
        "suite_b": b.suite_id,
        "out_csv": str(out_csv),
        "out_json": str(out_json),
        "alerts": list(alerts),
    }
