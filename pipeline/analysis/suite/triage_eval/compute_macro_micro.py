"""pipeline.analysis.suite.triage_eval.compute_macro_micro

Macro/micro precision + GT coverage aggregates for triage evaluation.

The aggregation bookkeeping is separated so the main compute loop stays readable.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Sequence, Tuple


@dataclass(frozen=True)
class _MacroMicroAgg:
    """Accumulators for macro/micro precision + coverage aggregates."""

    macro_prec_sum: Dict[str, Dict[int, float]]
    macro_prec_n: Dict[str, Dict[int, int]]
    micro_prec_tp: Dict[str, Dict[int, int]]
    micro_prec_denom: Dict[str, Dict[int, int]]

    macro_cov_sum: Dict[str, Dict[int, float]]
    macro_cov_n: Dict[str, Dict[int, int]]
    micro_cov_covered: Dict[str, Dict[int, int]]
    micro_cov_total: Dict[str, Dict[int, int]]


def _new_macro_micro_agg() -> _MacroMicroAgg:
    return _MacroMicroAgg(
        macro_prec_sum=defaultdict(lambda: defaultdict(float)),
        macro_prec_n=defaultdict(lambda: defaultdict(int)),
        micro_prec_tp=defaultdict(lambda: defaultdict(int)),
        micro_prec_denom=defaultdict(lambda: defaultdict(int)),
        macro_cov_sum=defaultdict(lambda: defaultdict(float)),
        macro_cov_n=defaultdict(lambda: defaultdict(int)),
        micro_cov_covered=defaultdict(lambda: defaultdict(int)),
        micro_cov_total=defaultdict(lambda: defaultdict(int)),
    )


def _compute_macro_micro(
    *,
    strategies: Sequence[str],
    k_list: Sequence[int],
    macro_prec_sum: Dict[str, Dict[int, float]],
    macro_prec_n: Dict[str, Dict[int, int]],
    micro_prec_tp: Dict[str, Dict[int, int]],
    micro_prec_denom: Dict[str, Dict[int, int]],
    macro_cov_sum: Dict[str, Dict[int, float]],
    macro_cov_n: Dict[str, Dict[int, int]],
    micro_cov_covered: Dict[str, Dict[int, int]],
    micro_cov_total: Dict[str, Dict[int, int]],
) -> Tuple[Dict[str, Dict[str, Dict[str, Any]]], Dict[str, Dict[str, Dict[str, Any]]]]:
    macro: Dict[str, Dict[str, Dict[str, Any]]] = {}
    micro: Dict[str, Dict[str, Dict[str, Any]]] = {}

    for strat in strategies:
        macro[strat] = {}
        micro[strat] = {}
        for k in k_list:
            p_n = macro_prec_n[strat].get(k, 0)
            p_sum = macro_prec_sum[strat].get(k, 0.0)
            c_n = macro_cov_n[strat].get(k, 0)
            c_sum = macro_cov_sum[strat].get(k, 0.0)

            macro[strat][str(k)] = {
                "precision": None if p_n == 0 else round(float(p_sum) / float(p_n), 6),
                "precision_cases": int(p_n),
                "gt_coverage": None if c_n == 0 else round(float(c_sum) / float(c_n), 6),
                "gt_coverage_cases": int(c_n),
            }

            tp = micro_prec_tp[strat].get(k, 0)
            denom = micro_prec_denom[strat].get(k, 0)
            covered = micro_cov_covered[strat].get(k, 0)
            total_gt = micro_cov_total[strat].get(k, 0)

            micro[strat][str(k)] = {
                "precision": None if denom == 0 else round(float(tp) / float(denom), 6),
                "tp_at_k": int(tp),
                "denom_at_k": int(denom),
                "gt_coverage": None
                if total_gt == 0
                else round(float(covered) / float(total_gt), 6),
                "gt_covered_at_k": int(covered),
                "gt_total": int(total_gt),
            }

    return macro, micro


__all__ = [
    "_MacroMicroAgg",
    "_new_macro_micro_agg",
    "_compute_macro_micro",
]
