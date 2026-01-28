"""pipeline.analysis.suite.triage_eval.compute_deltas

Computation of deltas (vs baseline) for triage evaluation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence, Tuple

from .compute_helpers import _delta, _opt_float
from .metrics import _to_int


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
            (strat_prec - base_prec) if (base_prec is not None and strat_prec is not None) else None
        )
        cov_delta = (
            (strat_cov - base_cov) if (base_cov is not None and strat_cov is not None) else None
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
                "baseline_precision": "" if base_prec is None else round(float(base_prec), 6),
                "strategy_precision": "" if strat_prec is None else round(float(strat_prec), 6),
                "precision_delta": "" if prec_delta is None else round(float(prec_delta), 6),
                "baseline_gt_coverage": "" if base_cov is None else round(float(base_cov), 6),
                "strategy_gt_coverage": "" if strat_cov is None else round(float(strat_cov), 6),
                "gt_coverage_delta": "" if cov_delta is None else round(float(cov_delta), 6),
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
    "_compute_deltas_by_case",
    "_compute_delta_vs_baseline",
]
