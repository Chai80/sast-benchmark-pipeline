"""pipeline.analysis.suite.triage_eval.compute_helpers

Small helper functions used across triage evaluation computation modules.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence


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
        cal.get("tool_stats_by_owasp") if isinstance(cal.get("tool_stats_by_owasp"), dict) else {}
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


__all__ = [
    "_opt_float",
    "_safe_div",
    "_delta",
    "_compute_topk_focus",
    "_compute_calibration_context",
]
