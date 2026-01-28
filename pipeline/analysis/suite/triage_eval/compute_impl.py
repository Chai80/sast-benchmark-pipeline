"""pipeline.analysis.suite.triage_eval.compute_impl

Implementation of :func:`compute_triage_eval`.

The public module :mod:`pipeline.analysis.suite.triage_eval.compute` is kept as
a small facade; this module holds the (still sizeable) implementation and
orchestrates the helper submodules.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set

from .compute_case_tables import (
    _build_by_case_rows_for_case_strategy,
    _build_topk_rows_for_case_strategy,
    _classify_case,
    _update_tool_contribution_counts,
)
from .compute_deltas import _compute_delta_vs_baseline, _compute_deltas_by_case
from .compute_helpers import _compute_calibration_context, _compute_topk_focus
from .compute_macro_micro import _new_macro_micro_agg, _compute_macro_micro
from .compute_types import TriageEvalComputeResult
from .metrics import _load_case_gt_ids
from .tool_marginal import _compute_tool_marginal_value, _compute_tool_utility


RankFn = Callable[[List[Dict[str, str]]], List[Dict[str, str]]]


def compute_triage_eval(
    *,
    sid: str,
    cases_dir: Any,
    case_ids: Sequence[str],
    by_case: Dict[str, List[Dict[str, str]]],
    strategies: Dict[str, RankFn],
    k_list: Sequence[int],
    max_k: int,
    cal: Optional[Dict[str, Any]],
    include_tool_marginal: bool,
) -> TriageEvalComputeResult:
    """Compute suite-level triage evaluation tables (no file I/O)."""

    # --- Accumulators -------------------------------------------------
    by_case_rows: List[Dict[str, Any]] = []
    cases_with_gt: List[str] = []
    cases_without_gt: List[str] = []
    cases_no_clusters: List[str] = []
    cases_with_gt_but_no_clusters: List[str] = []
    cases_with_gt_but_no_overlaps: List[str] = []

    case_has_gt: Dict[str, bool] = {}
    case_gt_total: Dict[str, int] = {}

    topk_rows: List[Dict[str, Any]] = []

    agg = _new_macro_micro_agg()

    gt_cover_tools: Dict[str, Set[str]] = defaultdict(set)
    tool_neg_clusters: Dict[str, int] = defaultdict(int)
    tool_excl_neg_clusters: Dict[str, int] = defaultdict(int)

    cases_dir_path = Path(cases_dir)

    # --- Per-case eval -------------------------------------------------
    for case_id in case_ids:
        case_rows = list(by_case.get(case_id) or [])
        n_clusters = len(case_rows)

        gt_ids, has_gt = _load_case_gt_ids(cases_dir_path / case_id)
        gt_total = len(gt_ids)

        case_has_gt[case_id] = bool(has_gt)
        case_gt_total[case_id] = int(gt_total)

        _classify_case(
            case_id=case_id,
            n_clusters=n_clusters,
            has_gt=bool(has_gt),
            case_rows=case_rows,
            cases_with_gt=cases_with_gt,
            cases_without_gt=cases_without_gt,
            cases_no_clusters=cases_no_clusters,
            cases_with_gt_but_no_clusters=cases_with_gt_but_no_clusters,
            cases_with_gt_but_no_overlaps=cases_with_gt_but_no_overlaps,
        )

        for strat, rank_fn in strategies.items():
            ordered = rank_fn(case_rows)

            topk_rows.extend(
                _build_topk_rows_for_case_strategy(
                    sid=sid,
                    case_id=case_id,
                    strat=strat,
                    ordered=ordered,
                    has_gt=bool(has_gt),
                    gt_total=int(gt_total),
                    max_k=int(max_k),
                )
            )

            by_case_rows.extend(
                _build_by_case_rows_for_case_strategy(
                    sid=sid,
                    case_id=case_id,
                    strat=strat,
                    ordered=ordered,
                    k_list=k_list,
                    n_clusters=int(n_clusters),
                    has_gt=bool(has_gt),
                    gt_total=int(gt_total),
                    agg=agg,
                )
            )

        _update_tool_contribution_counts(
            case_rows=case_rows,
            has_gt=bool(has_gt),
            gt_cover_tools=gt_cover_tools,
            tool_neg_clusters=tool_neg_clusters,
            tool_excl_neg_clusters=tool_excl_neg_clusters,
        )

    deltas_rows = _compute_deltas_by_case(sid=sid, by_case_rows=by_case_rows)

    macro, micro = _compute_macro_micro(
        strategies=list(strategies.keys()),
        k_list=k_list,
        macro_prec_sum=agg.macro_prec_sum,
        macro_prec_n=agg.macro_prec_n,
        micro_prec_tp=agg.micro_prec_tp,
        micro_prec_denom=agg.micro_prec_denom,
        macro_cov_sum=agg.macro_cov_sum,
        macro_cov_n=agg.macro_cov_n,
        micro_cov_covered=agg.micro_cov_covered,
        micro_cov_total=agg.micro_cov_total,
    )

    delta_vs_baseline = _compute_delta_vs_baseline(
        strategies=list(strategies.keys()),
        k_list=k_list,
        macro=macro,
        micro=micro,
    )

    tool_rows, all_tools = _compute_tool_utility(
        sid=sid,
        gt_cover_tools=gt_cover_tools,
        tool_neg_clusters=tool_neg_clusters,
        tool_excl_neg_clusters=tool_excl_neg_clusters,
    )

    tool_marginal_rows: List[Dict[str, Any]] = []
    if include_tool_marginal:
        tool_marginal_rows = _compute_tool_marginal_value(
            sid=sid,
            all_tools=all_tools,
            case_ids=case_ids,
            by_case=by_case,
            case_has_gt=case_has_gt,
            case_gt_total=case_gt_total,
            k_list=k_list,
            cal=cal,
            tool_rows=tool_rows,
        )

    topk_focus = _compute_topk_focus(
        k_list=k_list,
        strategies=list(strategies.keys()),
        macro=macro,
        micro=micro,
    )
    calibration_context = _compute_calibration_context(cal)

    return TriageEvalComputeResult(
        by_case_rows=by_case_rows,
        deltas_by_case_rows=deltas_rows,
        topk_rows=topk_rows,
        tool_rows=tool_rows,
        tool_marginal_rows=tool_marginal_rows,
        macro=macro,
        micro=micro,
        delta_vs_baseline=delta_vs_baseline,
        topk_focus=topk_focus,
        calibration_context=calibration_context,
        cases_with_gt=cases_with_gt,
        cases_without_gt=cases_without_gt,
        cases_no_clusters=cases_no_clusters,
        cases_with_gt_but_no_clusters=cases_with_gt_but_no_clusters,
        cases_with_gt_but_no_overlaps=cases_with_gt_but_no_overlaps,
    )


__all__ = [
    "compute_triage_eval",
    "RankFn",
]
