"""pipeline.analysis.suite.triage_eval.compute_tables

Table-building and aggregation helpers for triage evaluation.

This module consolidates the former split modules:
- compute_macro_micro.py
- compute_case_tables.py

to reduce file count while keeping the main compute loop readable.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Set, Tuple

from .metrics import _gt_ids_for_row, _to_int, _tools_for_row


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


def _classify_case(
    *,
    case_id: str,
    n_clusters: int,
    has_gt: bool,
    case_rows: Sequence[Dict[str, str]],
    cases_with_gt: List[str],
    cases_without_gt: List[str],
    cases_no_clusters: List[str],
    cases_with_gt_but_no_clusters: List[str],
    cases_with_gt_but_no_overlaps: List[str],
) -> None:
    """Update case classification lists (ordering preserved)."""

    if n_clusters == 0:
        cases_no_clusters.append(case_id)

    if has_gt:
        cases_with_gt.append(case_id)
    else:
        cases_without_gt.append(case_id)

    if has_gt and n_clusters == 0:
        cases_with_gt_but_no_clusters.append(case_id)

    if has_gt and n_clusters > 0:
        any_pos = any(_to_int(r.get("gt_overlap"), 0) == 1 for r in case_rows)
        if not any_pos:
            cases_with_gt_but_no_overlaps.append(case_id)


def _build_topk_rows_for_case_strategy(
    *,
    sid: str,
    case_id: str,
    strat: str,
    ordered: Sequence[Dict[str, str]],
    has_gt: bool,
    gt_total: int,
    max_k: int,
) -> List[Dict[str, Any]]:
    if max_k <= 0 or not ordered:
        return []

    out: List[Dict[str, Any]] = []

    covered_so_far: Set[str] = set()
    max_rank = min(int(max_k), len(ordered))

    for idx, r in enumerate(ordered[:max_rank], start=1):
        ids = _gt_ids_for_row(r) if has_gt else []
        if has_gt and gt_total:
            covered_so_far.update(ids)
            cum_cov: float | None = float(len(covered_so_far)) / float(gt_total)
        else:
            cum_cov = None

        out.append(
            {
                "suite_id": sid,
                "case_id": case_id,
                "strategy": strat,
                "rank": int(idx),
                "cluster_id": str(r.get("cluster_id") or ""),
                "tool_count": _to_int(r.get("tool_count"), 0),
                "tools_json": str(r.get("tools_json") or ""),
                "tools": str(r.get("tools") or ""),
                "max_severity": str(r.get("max_severity") or ""),
                "max_severity_rank": _to_int(r.get("max_severity_rank"), 0),
                "finding_count": _to_int(r.get("finding_count"), 0),
                "file_path": str(r.get("file_path") or ""),
                "start_line": _to_int(r.get("start_line"), 0),
                "triage_rank": _to_int(r.get("triage_rank"), 0),
                "triage_score_v1": str(r.get("triage_score_v1") or ""),
                "gt_overlap": _to_int(r.get("gt_overlap"), 0),
                "gt_overlap_ids_json": str(r.get("gt_overlap_ids_json") or ""),
                "gt_overlap_ids": str(r.get("gt_overlap_ids") or ""),
                "gt_overlap_ids_count": int(len(ids)),
                "has_gt": int(bool(has_gt)),
                "gt_total": int(gt_total),
                "cumulative_gt_covered": "" if cum_cov is None else int(len(covered_so_far)),
                "cumulative_gt_coverage": "" if cum_cov is None else round(float(cum_cov), 6),
            }
        )

    return out


def _build_by_case_rows_for_case_strategy(
    *,
    sid: str,
    case_id: str,
    strat: str,
    ordered: Sequence[Dict[str, str]],
    k_list: Sequence[int],
    n_clusters: int,
    has_gt: bool,
    gt_total: int,
    agg: _MacroMicroAgg,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for k in k_list:
        kk = int(k)
        k_eff = min(kk, len(ordered))
        top = list(ordered[:k_eff])

        tp = sum(1 for r in top if _to_int(r.get("gt_overlap"), 0) == 1) if has_gt else 0
        denom = int(k_eff) if has_gt else 0
        prec = (float(tp) / float(denom)) if denom else None

        covered_ids: Set[str] = set()
        if has_gt and gt_total:
            for r in top:
                covered_ids.update(_gt_ids_for_row(r))
        covered = len(covered_ids) if (has_gt and gt_total) else 0
        cov = (float(covered) / float(gt_total)) if (has_gt and gt_total) else None

        out.append(
            {
                "suite_id": sid,
                "case_id": case_id,
                "strategy": strat,
                "k": int(kk),
                "n_clusters": int(n_clusters),
                "has_gt": int(bool(has_gt)),
                "gt_total": int(gt_total),
                "precision": "" if prec is None else round(float(prec), 6),
                "tp_at_k": int(tp),
                "denom_at_k": int(denom),
                "gt_coverage": "" if cov is None else round(float(cov), 6),
                "gt_covered_at_k": int(covered),
            }
        )

        if has_gt and denom:
            agg.macro_prec_sum[strat][kk] += float(tp) / float(denom)
            agg.macro_prec_n[strat][kk] += 1
            agg.micro_prec_tp[strat][kk] += int(tp)
            agg.micro_prec_denom[strat][kk] += int(denom)

        if has_gt and gt_total:
            agg.macro_cov_sum[strat][kk] += float(covered) / float(gt_total)
            agg.macro_cov_n[strat][kk] += 1
            agg.micro_cov_covered[strat][kk] += int(covered)
            agg.micro_cov_total[strat][kk] += int(gt_total)

    return out


def _update_tool_contribution_counts(
    *,
    case_rows: Sequence[Dict[str, str]],
    has_gt: bool,
    gt_cover_tools: Dict[str, Set[str]],
    tool_neg_clusters: Dict[str, int],
    tool_excl_neg_clusters: Dict[str, int],
) -> None:
    if not has_gt:
        return

    for r in case_rows:
        tools = _tools_for_row(r)
        if _to_int(r.get("gt_overlap"), 0) == 1:
            for gid in _gt_ids_for_row(r):
                gt_cover_tools[gid].update(set(tools))
        else:
            if tools:
                for t in tools:
                    tool_neg_clusters[t] += 1
                if len(tools) == 1:
                    tool_excl_neg_clusters[tools[0]] += 1


__all__ = [
    "_MacroMicroAgg",
    "_new_macro_micro_agg",
    "_compute_macro_micro",
    "_classify_case",
    "_build_topk_rows_for_case_strategy",
    "_build_by_case_rows_for_case_strategy",
    "_update_tool_contribution_counts",
]
