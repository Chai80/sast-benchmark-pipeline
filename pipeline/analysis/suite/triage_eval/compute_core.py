"""pipeline.analysis.suite.triage_eval.compute_core

Core shared types and helpers for triage evaluation computation.

This module consolidates the former split modules:
- compute_types.py
- compute_helpers.py
- compute_deltas.py

into a single cohesive module to reduce file count while keeping each file
under the project's ~300 LOC preference.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .metrics import _to_int


@dataclass(frozen=True)
class TriageEvalComputeResult:
    """All computed tables + summary sub-structures.

    The public build_triage_eval() entrypoint writes these tables to disk and
    assembles the final summary JSON.
    """

    by_case_rows: List[Dict[str, Any]]
    deltas_by_case_rows: List[Dict[str, Any]]
    topk_rows: List[Dict[str, Any]]

    tool_rows: List[Dict[str, Any]]
    tool_marginal_rows: List[Dict[str, Any]]

    macro: Dict[str, Dict[str, Dict[str, Any]]]
    micro: Dict[str, Dict[str, Dict[str, Any]]]
    delta_vs_baseline: Dict[str, Any]

    topk_focus: Dict[str, Any]
    calibration_context: Optional[Dict[str, Any]]

    cases_with_gt: List[str]
    cases_without_gt: List[str]
    cases_no_clusters: List[str]
    cases_with_gt_but_no_clusters: List[str]
    cases_with_gt_but_no_overlaps: List[str]


def _opt_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    s = str(v).strip()
    if s == "":
        return None
    try:
        return float(s)
    except Exception:
        return None


def _safe_div(num: int, den: int) -> Optional[float]:
    if den <= 0:
        return None
    return float(num) / float(den)


def _delta(a: Any, b: Any) -> Optional[float]:
    if a is None or b is None:
        return None
    try:
        return round(float(a) - float(b), 6)
    except Exception:
        return None


def _compute_topk_focus(
    *,
    k_list: Sequence[int],
    strategies: Sequence[str],
    macro: Dict[str, Dict[str, Dict[str, Any]]],
    micro: Dict[str, Dict[str, Dict[str, Any]]],
) -> Dict[str, Any]:
    focus_ks = [k for k in (10, 25, 50) if k in k_list]
    focus_strategies = [
        s for s in ("baseline", "calibrated_global", "calibrated") if s in strategies
    ]

    topk_focus: Dict[str, Any] = {
        "ks": list(focus_ks),
        "strategies": list(focus_strategies),
        "macro": {},
        "micro": {},
    }

    for agg_name, agg in (("macro", macro), ("micro", micro)):
        for k in focus_ks:
            kk = str(k)
            topk_focus[agg_name][kk] = {}
            for strat in focus_strategies:
                mm = (agg.get(strat) or {}).get(kk) or {}
                topk_focus[agg_name][kk][strat] = {
                    "precision": mm.get("precision"),
                    "gt_coverage": mm.get("gt_coverage"),
                }

    return topk_focus


def _compute_calibration_context(
    cal: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not cal or not isinstance(cal, dict):
        return None

    scoring = cal.get("scoring") if isinstance(cal.get("scoring"), dict) else {}
    min_support_by_owasp = int(scoring.get("min_support_by_owasp", 10))

    fallback: List[str] = []
    by_owasp = (
        cal.get("tool_stats_by_owasp")
        if isinstance(cal.get("tool_stats_by_owasp"), dict)
        else {}
    )
    if isinstance(by_owasp, dict):
        for oid, v in by_owasp.items():
            if not isinstance(v, dict):
                continue
            sup = v.get("support") if isinstance(v.get("support"), dict) else {}
            clusters_n = int(sup.get("clusters") or 0)
            if clusters_n < min_support_by_owasp:
                fallback.append(str(oid))

    return {
        "min_support_by_owasp": int(min_support_by_owasp),
        "owasp_fallback_ids": sorted({str(x) for x in fallback if str(x)}),
    }


def _compute_deltas_by_case(
    *,
    sid: str,
    by_case_rows: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Per-case deltas vs baseline (additive inspection table)."""

    baseline_index: Dict[Tuple[str, int], Dict[str, Any]] = {}
    for r in by_case_rows:
        if str(r.get("strategy")) != "baseline":
            continue
        cid = str(r.get("case_id") or "").strip()
        k = _to_int(r.get("k"), 0)
        if cid and k:
            baseline_index[(cid, k)] = dict(r)

    out: List[Dict[str, Any]] = []
    for r in by_case_rows:
        strat = str(r.get("strategy") or "")
        if strat == "baseline":
            continue

        cid = str(r.get("case_id") or "").strip()
        k = _to_int(r.get("k"), 0)
        base = baseline_index.get((cid, k))
        if not base:
            continue

        base_prec = _opt_float(base.get("precision"))
        strat_prec = _opt_float(r.get("precision"))
        base_cov = _opt_float(base.get("gt_coverage"))
        strat_cov = _opt_float(r.get("gt_coverage"))

        prec_delta = (
            (strat_prec - base_prec)
            if (base_prec is not None and strat_prec is not None)
            else None
        )
        cov_delta = (
            (strat_cov - base_cov)
            if (base_cov is not None and strat_cov is not None)
            else None
        )

        out.append(
            {
                "suite_id": sid,
                "case_id": cid,
                "strategy": strat,
                "k": int(k),
                "n_clusters": _to_int(r.get("n_clusters"), 0),
                "has_gt": _to_int(r.get("has_gt"), 0),
                "gt_total": _to_int(r.get("gt_total"), 0),
                "baseline_precision": ""
                if base_prec is None
                else round(float(base_prec), 6),
                "strategy_precision": ""
                if strat_prec is None
                else round(float(strat_prec), 6),
                "precision_delta": ""
                if prec_delta is None
                else round(float(prec_delta), 6),
                "baseline_gt_coverage": ""
                if base_cov is None
                else round(float(base_cov), 6),
                "strategy_gt_coverage": ""
                if strat_cov is None
                else round(float(strat_cov), 6),
                "gt_coverage_delta": ""
                if cov_delta is None
                else round(float(cov_delta), 6),
            }
        )

    out.sort(
        key=lambda r: (
            str(r.get("case_id") or ""),
            str(r.get("strategy") or ""),
            int(r.get("k") or 0),
        )
    )
    return out


def _compute_delta_vs_baseline(
    *,
    strategies: Sequence[str],
    k_list: Sequence[int],
    macro: Dict[str, Dict[str, Dict[str, Any]]],
    micro: Dict[str, Dict[str, Dict[str, Any]]],
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"macro": {}, "micro": {}}

    for strat in strategies:
        if strat == "baseline":
            continue
        if strat not in macro or "baseline" not in macro:
            continue

        m_out: Dict[str, Any] = {}
        mi_out: Dict[str, Any] = {}

        for k in k_list:
            kk = str(k)
            base_m = macro.get("baseline", {}).get(kk, {})
            cur_m = macro.get(strat, {}).get(kk, {})
            base_mi = micro.get("baseline", {}).get(kk, {})
            cur_mi = micro.get(strat, {}).get(kk, {})

            m_out[kk] = {
                "precision": _delta(cur_m.get("precision"), base_m.get("precision")),
                "gt_coverage": _delta(cur_m.get("gt_coverage"), base_m.get("gt_coverage")),
            }
            mi_out[kk] = {
                "precision": _delta(cur_mi.get("precision"), base_mi.get("precision")),
                "gt_coverage": _delta(cur_mi.get("gt_coverage"), base_mi.get("gt_coverage")),
            }

        out["macro"][strat] = m_out
        out["micro"][strat] = mi_out

    return out


__all__ = [
    "TriageEvalComputeResult",
    "_opt_float",
    "_safe_div",
    "_delta",
    "_compute_topk_focus",
    "_compute_calibration_context",
    "_compute_deltas_by_case",
    "_compute_delta_vs_baseline",
]
