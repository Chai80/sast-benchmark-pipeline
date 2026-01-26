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

from .diff import _delta, _to_int
from .load import (
    SuiteArtifacts,
    _dataset_counts,
    _extract_eval,
    _extract_gt_policy,
    _load_calibration_weights,
    _load_suite_artifacts,
    _load_tool_marginal,
    _load_tool_utility,
)


SUITE_COMPARE_REPORT_SCHEMA_V1 = "suite_compare_report_v1"


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _append_row(
    rows: List[Dict[str, Any]],
    *,
    section: str,
    name: str,
    a_val: Any,
    b_val: Any,
    delta_val: Any = None,
    tool: str = "",
    strategy: str = "",
    k: Any = "",
    notes: str = "",
) -> None:
    """Append one normalized comparison row."""

    rows.append(
        {
            "section": str(section),
            "name": str(name),
            "tool": str(tool or ""),
            "strategy": str(strategy or ""),
            "k": "" if k in (None, "") else int(k),
            "a": "" if a_val is None else a_val,
            "b": "" if b_val is None else b_val,
            "delta": "" if delta_val is None else delta_val,
            "notes": str(notes or ""),
        }
    )


def _pol_get(pol: Mapping[str, Any], path: Sequence[str]) -> Any:
    cur: Any = pol
    for key in path:
        if not isinstance(cur, Mapping):
            return None
        cur = cur.get(key)
    return cur


def _strategy_order(name: str) -> Tuple[int, str]:
    order = {"baseline": 0, "agreement": 1, "calibrated": 2}
    return (order.get(name, 99), str(name))


def _k_key(s: str) -> Tuple[int, str]:
    try:
        return (int(s), s)
    except Exception:
        return (10**9, s)


# ---------------------------------------------------------------------------
# Section emitters
# ---------------------------------------------------------------------------


def _append_policy_diff(
    rows: List[Dict[str, Any]], *, pol_a: Mapping[str, Any], pol_b: Mapping[str, Any]
) -> None:
    # Flat policy keys (keep CSV small)
    pol_fields: List[Tuple[str, Sequence[str]]] = [
        ("initial_gt_tolerance", ("initial_gt_tolerance",)),
        ("effective_gt_tolerance", ("effective_gt_tolerance",)),
        ("sweep.enabled", ("sweep", "enabled")),
        ("sweep.candidates", ("sweep", "candidates")),
        ("auto.enabled", ("auto", "enabled")),
        ("auto.min_fraction", ("auto", "min_fraction")),
    ]

    for name, path in pol_fields:
        va = _pol_get(pol_a, path)
        vb = _pol_get(pol_b, path)
        d = (
            _delta(va, vb)
            if isinstance(va, (int, float, str)) and isinstance(vb, (int, float, str))
            else None
        )
        _append_row(rows, section="policy", name=name, a_val=va, b_val=vb, delta_val=d)

    # Selection warnings are lists; represent as JSON strings.
    sel_warn_a = _pol_get(pol_a, ("auto", "warnings"))
    sel_warn_b = _pol_get(pol_b, ("auto", "warnings"))
    _append_row(
        rows,
        section="policy",
        name="auto.warnings",
        a_val=json.dumps(sel_warn_a or []),
        b_val=json.dumps(sel_warn_b or []),
        delta_val=None,
    )


def _append_scanner_config_diff(
    rows: List[Dict[str, Any]], *, sc_a: Mapping[str, Any], sc_b: Mapping[str, Any]
) -> None:
    # Config/profile changes are the most common explanation for "tool drift".
    _append_row(
        rows,
        section="scanner_config",
        name="profile",
        a_val=sc_a.get("profile"),
        b_val=sc_b.get("profile"),
    )
    _append_row(
        rows,
        section="scanner_config",
        name="profile_mode",
        a_val=sc_a.get("profile_mode"),
        b_val=sc_b.get("profile_mode"),
    )

    _append_row(
        rows,
        section="scanner_config",
        name="missing_tools",
        a_val=json.dumps(sc_a.get("missing_tools") or []),
        b_val=json.dumps(sc_b.get("missing_tools") or []),
        delta_val=None,
    )

    hashes_a = (
        sc_a.get("config_receipt_hashes")
        if isinstance(sc_a.get("config_receipt_hashes"), Mapping)
        else {}
    )
    hashes_b = (
        sc_b.get("config_receipt_hashes")
        if isinstance(sc_b.get("config_receipt_hashes"), Mapping)
        else {}
    )
    tools_cfg = sorted(set(list(hashes_a.keys()) + list(hashes_b.keys())))
    for t in tools_cfg:
        _append_row(
            rows,
            section="scanner_config",
            name="config_receipt_hashes",
            tool=str(t),
            a_val=json.dumps(hashes_a.get(t) or []),
            b_val=json.dumps(hashes_b.get(t) or []),
            delta_val=None,
        )


def _append_dataset_counts(
    rows: List[Dict[str, Any]], *, ds_a: Mapping[str, Any], ds_b: Mapping[str, Any]
) -> None:
    for key in ("clusters_total", "clusters_gt_pos", "clusters_gt_neg", "cases_seen"):
        va = ds_a.get(key)
        vb = ds_b.get(key)
        _append_row(
            rows,
            section="dataset",
            name=key,
            a_val=va,
            b_val=vb,
            delta_val=_delta(va, vb),
        )


def _append_eval_diff(
    rows: List[Dict[str, Any]], *, eval_a: Mapping[str, Any], eval_b: Mapping[str, Any]
) -> None:
    for agg in ("micro", "macro"):
        obj_a = eval_a.get(agg) if isinstance(eval_a, dict) else {}
        obj_b = eval_b.get(agg) if isinstance(eval_b, dict) else {}

        strat_keys = sorted(
            set(list(obj_a.keys()) + list(obj_b.keys())), key=_strategy_order
        )

        for strat in strat_keys:
            ka_obj = obj_a.get(strat) if isinstance(obj_a, dict) else {}
            kb_obj = obj_b.get(strat) if isinstance(obj_b, dict) else {}

            ks = set()
            if isinstance(ka_obj, Mapping):
                ks.update([str(k) for k in ka_obj.keys()])
            if isinstance(kb_obj, Mapping):
                ks.update([str(k) for k in kb_obj.keys()])

            for k_str in sorted(ks, key=_k_key):
                ra = ka_obj.get(k_str) if isinstance(ka_obj, Mapping) else None
                rb = kb_obj.get(k_str) if isinstance(kb_obj, Mapping) else None

                pa = ra.get("precision") if isinstance(ra, Mapping) else None
                pb = rb.get("precision") if isinstance(rb, Mapping) else None
                ca = ra.get("gt_coverage") if isinstance(ra, Mapping) else None
                cb = rb.get("gt_coverage") if isinstance(rb, Mapping) else None

                _append_row(
                    rows,
                    section=f"eval_{agg}",
                    name="precision",
                    strategy=strat,
                    k=_to_int(k_str, 0),
                    a_val=pa,
                    b_val=pb,
                    delta_val=_delta(pa, pb),
                )
                _append_row(
                    rows,
                    section=f"eval_{agg}",
                    name="gt_coverage",
                    strategy=strat,
                    k=_to_int(k_str, 0),
                    a_val=ca,
                    b_val=cb,
                    delta_val=_delta(ca, cb),
                )


def _append_calibration_global(
    rows: List[Dict[str, Any]],
    *,
    cal_w_a: Mapping[str, Any],
    cal_w_b: Mapping[str, Any],
) -> None:
    tools = sorted(set(list(cal_w_a.keys()) + list(cal_w_b.keys())))
    for t in tools:
        wa = cal_w_a.get(t)
        wb = cal_w_b.get(t)
        _append_row(
            rows,
            section="calibration_weight_global",
            name="weight",
            tool=str(t),
            a_val=wa,
            b_val=wb,
            delta_val=_delta(wa, wb),
        )


def _append_calibration_by_owasp(
    rows: List[Dict[str, Any]],
    *,
    cal_by_owasp_a: Mapping[str, Any],
    cal_by_owasp_b: Mapping[str, Any],
) -> None:
    # Best-effort per-OWASP weights
    owasp_ids = sorted(set(list(cal_by_owasp_a.keys()) + list(cal_by_owasp_b.keys())))
    for oid in owasp_ids:
        wa_map = cal_by_owasp_a.get(oid, {})
        wb_map = cal_by_owasp_b.get(oid, {})
        tools2 = sorted(set(list(wa_map.keys()) + list(wb_map.keys())))
        for t in tools2:
            _append_row(
                rows,
                section="calibration_weight_by_owasp",
                name=f"weight:{oid}",
                tool=str(t),
                a_val=wa_map.get(t),
                b_val=wb_map.get(t),
                delta_val=_delta(wa_map.get(t), wb_map.get(t)),
            )


def _append_tool_utility_diff(
    rows: List[Dict[str, Any]], *, util_a: Mapping[str, Any], util_b: Mapping[str, Any]
) -> None:
    util_tools = sorted(set(list(util_a.keys()) + list(util_b.keys())))
    for t in util_tools:
        ra = util_a.get(t, {})
        rb = util_b.get(t, {})
        for field in (
            "gt_ids_covered",
            "unique_gt_ids",
            "neg_clusters",
            "exclusive_neg_clusters",
        ):
            va = ra.get(field)
            vb = rb.get(field)
            _append_row(
                rows,
                section="tool_utility",
                name=field,
                tool=str(t),
                a_val=va,
                b_val=vb,
                delta_val=_delta(va, vb),
            )


def _append_tool_marginal_diff(
    rows: List[Dict[str, Any]],
    *,
    marg_a: Mapping[Tuple[str, str, int], Any],
    marg_b: Mapping[Tuple[str, str, int], Any],
) -> None:
    keys = sorted(set(list(marg_a.keys()) + list(marg_b.keys())))
    for tool, strat, k in keys:
        ra = marg_a.get((tool, strat, k), {})
        rb = marg_b.get((tool, strat, k), {})
        for field in ("delta_precision", "delta_gt_coverage", "delta_neg_in_topk"):
            va = ra.get(field)
            vb = rb.get(field)
            _append_row(
                rows,
                section="tool_marginal",
                name=field,
                tool=str(tool),
                strategy=str(strat),
                k=int(k),
                a_val=va,
                b_val=vb,
                delta_val=_delta(va, vb),
            )


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

    try:
        eff_a = _pol_get(pol_a, ("effective_gt_tolerance",))
        eff_b = _pol_get(pol_b, ("effective_gt_tolerance",))
        if _to_int(eff_a, 0) != _to_int(eff_b, 0):
            alerts.append(f"GT tolerance changed: {eff_a} -> {eff_b}")
    except Exception:
        pass

    # Scanner profile/config drift (the most common "it's just config" critique)
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
                alerts.append(
                    f"Scanner config signature changed for tools: {changed_tools}"
                )
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


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------


def build_suite_compare_report(
    *,
    suite_dir_a: str | Path,
    suite_dir_b: str | Path,
    out_suite_dir: Optional[str | Path] = None,
    out_basename: str = "suite_compare_report",
    include_tool_marginal: bool = True,
) -> Dict[str, Any]:
    """Compare two suite dirs and write a report.

    Parameters
    ----------
    suite_dir_a, suite_dir_b:
        Existing suite directories, e.g. runs/suites/20260101T...Z.

    out_suite_dir:
        Where to write the report. Defaults to suite_dir_a.

    out_basename:
        Basename for output files under analysis/_tables.

    include_tool_marginal:
        If True, include triage_tool_marginal.csv comparisons when both suites
        have the file.
    """

    a_dir = Path(suite_dir_a).resolve()
    b_dir = Path(suite_dir_b).resolve()

    out_dir = Path(out_suite_dir).resolve() if out_suite_dir else a_dir
    out_tables = out_dir / "analysis" / "_tables"

    a, warn_a = _load_suite_artifacts(a_dir)
    b, warn_b = _load_suite_artifacts(b_dir)

    # Require eval summaries for meaningful drift comparison.
    if a.eval_summary is None or b.eval_summary is None:
        missing: List[str] = []
        if a.eval_summary is None:
            missing.append(f"{a.suite_id}: triage_eval_summary.json")
        if b.eval_summary is None:
            missing.append(f"{b.suite_id}: triage_eval_summary.json")
        raise SystemExit(
            "Cannot compare suites; missing required eval summary: "
            + ", ".join(missing)
        )

    # Extract key inputs.
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

    # --- Diff sections ----------------------------------------------
    _append_policy_diff(rows_csv, pol_a=pol_a, pol_b=pol_b)

    sc_a = a.scanner_config if isinstance(a.scanner_config, Mapping) else {}
    sc_b = b.scanner_config if isinstance(b.scanner_config, Mapping) else {}
    _append_scanner_config_diff(rows_csv, sc_a=sc_a, sc_b=sc_b)

    _append_dataset_counts(rows_csv, ds_a=ds_a, ds_b=ds_b)
    _append_eval_diff(rows_csv, eval_a=eval_a, eval_b=eval_b)
    _append_calibration_global(rows_csv, cal_w_a=cal_w_a, cal_w_b=cal_w_b)
    _append_calibration_by_owasp(
        rows_csv, cal_by_owasp_a=cal_by_owasp_a, cal_by_owasp_b=cal_by_owasp_b
    )
    _append_tool_utility_diff(rows_csv, util_a=util_a, util_b=util_b)

    if include_tool_marginal and marg_a and marg_b:
        _append_tool_marginal_diff(rows_csv, marg_a=marg_a, marg_b=marg_b)

    # --- Alerts ------------------------------------------------------
    alerts = _build_alerts(
        a=a, b=b, pol_a=pol_a, pol_b=pol_b, warn_a=warn_a, warn_b=warn_b
    )
    _append_alert_rows(rows_csv, alerts=alerts)

    # Stable sort for CSV.
    rows_csv.sort(key=_row_key)

    out_json = out_tables / f"{out_basename}.json"
    out_csv = out_tables / f"{out_basename}.csv"

    report: Dict[str, Any] = {
        "schema_version": SUITE_COMPARE_REPORT_SCHEMA_V1,
        "generated_at": _now_iso_utc(),
        "suite_a": {
            "suite_id": a.suite_id,
            "suite_dir": str(a.suite_dir),
            "suite_json_path": str(a.suite_json_path),
            "qa_manifest_path": ""
            if a.qa_manifest_path is None
            else str(a.qa_manifest_path),
            "eval_summary_path": ""
            if a.eval_summary_path is None
            else str(a.eval_summary_path),
            "dataset_csv": "" if a.dataset_csv is None else str(a.dataset_csv),
            "tool_utility_csv": ""
            if a.tool_utility_csv is None
            else str(a.tool_utility_csv),
            "calibration_json": ""
            if a.calibration_json is None
            else str(a.calibration_json),
            "tool_marginal_csv": ""
            if a.tool_marginal_csv is None
            else str(a.tool_marginal_csv),
        },
        "suite_b": {
            "suite_id": b.suite_id,
            "suite_dir": str(b.suite_dir),
            "suite_json_path": str(b.suite_json_path),
            "qa_manifest_path": ""
            if b.qa_manifest_path is None
            else str(b.qa_manifest_path),
            "eval_summary_path": ""
            if b.eval_summary_path is None
            else str(b.eval_summary_path),
            "dataset_csv": "" if b.dataset_csv is None else str(b.dataset_csv),
            "tool_utility_csv": ""
            if b.tool_utility_csv is None
            else str(b.tool_utility_csv),
            "calibration_json": ""
            if b.calibration_json is None
            else str(b.calibration_json),
            "tool_marginal_csv": ""
            if b.tool_marginal_csv is None
            else str(b.tool_marginal_csv),
        },
        "warnings": {
            "suite_a": list(sorted(set(warn_a))),
            "suite_b": list(sorted(set(warn_b))),
        },
        "alerts": list(alerts),
        "diff": {
            "gt_tolerance_policy": {
                "a": pol_a,
                "b": pol_b,
            },
            "scanner_config": {
                "a": a.scanner_config,
                "b": b.scanner_config,
            },
            "dataset_counts": {
                "a": ds_a,
                "b": ds_b,
            },
            "calibration_weights_global": {
                "a": cal_w_a,
                "b": cal_w_b,
            },
            "tool_utility": {
                "a": util_a,
                "b": util_b,
            },
        },
        "out_csv": str(out_csv),
        "out_json": str(out_json),
    }

    # Write outputs.
    write_json(out_json, report)
    write_csv(
        out_csv,
        rows_csv,
        fieldnames=[
            "section",
            "name",
            "tool",
            "strategy",
            "k",
            "a",
            "b",
            "delta",
            "notes",
        ],
    )

    return {
        "suite_a": a.suite_id,
        "suite_b": b.suite_id,
        "out_csv": str(out_csv),
        "out_json": str(out_json),
        "alerts": list(alerts),
    }
