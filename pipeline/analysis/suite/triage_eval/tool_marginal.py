"""Tool-centric triage-eval computations.

Extracted from `compute.py` to keep the main module smaller and easier to scan.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from .io import _parse_tool_counts_json, _stable_tool_counts_json
from .metrics import _compute_tool_cluster_counts, _micro_totals_for_rows, _metrics_from_totals, _to_int, _tools_for_row
from .strategies import _build_marginal_strategies


def _compute_tool_utility(
    *,
    sid: str,
    gt_cover_tools: Dict[str, Set[str]],
    tool_neg_clusters: Dict[str, int],
    tool_excl_neg_clusters: Dict[str, int],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    unique_gt_by_tool: Dict[str, int] = defaultdict(int)
    total_gt_by_tool: Dict[str, int] = defaultdict(int)
    for gid, tools in gt_cover_tools.items():
        for t in tools:
            total_gt_by_tool[t] += 1
        if len(tools) == 1:
            unique_gt_by_tool[next(iter(tools))] += 1

    all_tools = sorted(set(list(total_gt_by_tool.keys()) + list(tool_neg_clusters.keys())))

    tool_rows: List[Dict[str, Any]] = []
    for t in all_tools:
        tool_rows.append(
            {
                "suite_id": sid,
                "tool": t,
                "gt_ids_covered": int(total_gt_by_tool.get(t, 0)),
                "unique_gt_ids": int(unique_gt_by_tool.get(t, 0)),
                "neg_clusters": int(tool_neg_clusters.get(t, 0)),
                "exclusive_neg_clusters": int(tool_excl_neg_clusters.get(t, 0)),
            }
        )

    return tool_rows, all_tools


def _drop_tool_from_row(row: Dict[str, str], tool: str) -> Optional[Dict[str, str]]:
    """Return a shallow-copied row with ``tool`` removed (or None if empty)."""

    tools = _tools_for_row(row)
    if tool not in tools:
        return dict(row)

    counts = _parse_tool_counts_json(str(row.get("tool_counts_json") or ""), tools)
    counts.pop(tool, None)
    counts = {k: int(v) for k, v in counts.items() if int(v) > 0}
    if not counts:
        return None

    rr = dict(row)
    new_tools = sorted(counts.keys())

    rr["tool_counts_json"] = _stable_tool_counts_json(counts)
    rr["tools_json"] = json.dumps(new_tools, ensure_ascii=False)
    rr["tools"] = ",".join(new_tools)
    rr["tool_count"] = str(int(len(new_tools)))
    rr["finding_count"] = str(int(sum(int(v) for v in counts.values())))

    # Force re-score under calibrated ranking.
    if "triage_score_v1" in rr:
        rr["triage_score_v1"] = ""

    return rr


def _drop_tool_by_case(
    *,
    by_case: Dict[str, List[Dict[str, str]]],
    tool: str,
    case_ids: Sequence[str],
    case_has_gt: Dict[str, bool],
) -> Dict[str, List[Dict[str, str]]]:
    """Drop a tool from all case rows (GT-only cases)"""

    dropped_by_case: Dict[str, List[Dict[str, str]]] = {}
    for cid in case_ids:
        if not case_has_gt.get(cid, False):
            continue
        case_rows = list(by_case.get(cid) or [])
        new_rows: List[Dict[str, str]] = []
        for r in case_rows:
            rr = _drop_tool_from_row(r, tool)
            if rr is not None:
                new_rows.append(rr)
        dropped_by_case[cid] = new_rows

    return dropped_by_case


def _build_tool_marginal_rows_for_tool(
    *,
    sid: str,
    tool: str,
    strategies: Sequence[str],
    k_list: Sequence[int],
    full_totals: Dict[str, Dict[int, Dict[str, int]]],
    drop_totals: Dict[str, Dict[int, Dict[str, int]]],
    util: Mapping[str, Any],
    cluster_counts: Mapping[str, int],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    for strat in strategies:
        for k in k_list:
            kk = int(k)
            full_m = _metrics_from_totals(full_totals.get(strat, {}).get(kk, {}))
            drop_m = _metrics_from_totals(drop_totals.get(strat, {}).get(kk, {}))

            p_full = full_m.get("precision")
            p_drop = drop_m.get("precision")
            c_full = full_m.get("gt_coverage")
            c_drop = drop_m.get("gt_coverage")

            dp = (
                (float(p_drop) - float(p_full))
                if (p_full is not None and p_drop is not None)
                else None
            )
            dc = (
                (float(c_drop) - float(c_full))
                if (c_full is not None and c_drop is not None)
                else None
            )

            neg_full = int(full_m.get("neg_in_topk") or 0)
            neg_drop = int(drop_m.get("neg_in_topk") or 0)

            rows.append(
                {
                    "suite_id": sid,
                    "tool": str(tool),
                    "strategy": str(strat),
                    "k": int(kk),
                    "precision_full": "" if p_full is None else round(float(p_full), 6),
                    "precision_drop": "" if p_drop is None else round(float(p_drop), 6),
                    "delta_precision": "" if dp is None else round(float(dp), 6),
                    "gt_coverage_full": "" if c_full is None else round(float(c_full), 6),
                    "gt_coverage_drop": "" if c_drop is None else round(float(c_drop), 6),
                    "delta_gt_coverage": "" if dc is None else round(float(dc), 6),
                    "neg_in_topk_full": int(neg_full),
                    "neg_in_topk_drop": int(neg_drop),
                    "delta_neg_in_topk": int(neg_drop) - int(neg_full),
                    "gt_ids_covered": int(util.get("gt_ids_covered") or 0),
                    "unique_gt_ids": int(util.get("unique_gt_ids") or 0),
                    "neg_clusters": int(util.get("neg_clusters") or 0),
                    "exclusive_neg_clusters": int(util.get("exclusive_neg_clusters") or 0),
                    "clusters_with_tool": int(cluster_counts.get("clusters_with_tool") or 0),
                    "clusters_exclusive_total": int(
                        cluster_counts.get("clusters_exclusive_total") or 0
                    ),
                    "clusters_exclusive_pos": int(
                        cluster_counts.get("clusters_exclusive_pos") or 0
                    ),
                    "clusters_exclusive_neg": int(
                        cluster_counts.get("clusters_exclusive_neg") or 0
                    ),
                }
            )

    return rows


def _compute_tool_marginal_value(
    *,
    sid: str,
    all_tools: Sequence[str],
    case_ids: Sequence[str],
    by_case: Dict[str, List[Dict[str, str]]],
    case_has_gt: Dict[str, bool],
    case_gt_total: Dict[str, int],
    k_list: Sequence[int],
    cal: Optional[Dict[str, Any]],
    tool_rows: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Drop-one tool marginal value analysis.

    Logic is preserved from the original monolithic build_triage_eval.
    """

    if not all_tools:
        return []

    cases_with_gt = [cid for cid in case_ids if bool(case_has_gt.get(cid, False))]
    if not cases_with_gt:
        return []

    tool_utility_by_tool: Dict[str, Dict[str, Any]] = {
        str(r.get("tool") or ""): dict(r) for r in tool_rows
    }

    strategies_marginal = _build_marginal_strategies(cal)

    full_totals: Dict[str, Dict[int, Dict[str, int]]] = {}
    for strat, rank_fn in strategies_marginal.items():
        full_totals[strat] = _micro_totals_for_rows(
            case_ids=case_ids,
            case_has_gt=case_has_gt,
            case_gt_total=case_gt_total,
            k_list=k_list,
            rows_by_case=by_case,
            rank_fn=rank_fn,
        )

    tool_cluster_counts = _compute_tool_cluster_counts(
        all_tools=all_tools,
        case_ids=case_ids,
        by_case=by_case,
        case_has_gt=case_has_gt,
    )

    tool_marginal_rows: List[Dict[str, Any]] = []

    for tool in all_tools:
        dropped_by_case = _drop_tool_by_case(
            by_case=by_case, tool=str(tool), case_ids=case_ids, case_has_gt=case_has_gt
        )

        drop_totals: Dict[str, Dict[int, Dict[str, int]]] = {}
        for strat, rank_fn in strategies_marginal.items():
            drop_totals[strat] = _micro_totals_for_rows(
                case_ids=case_ids,
                case_has_gt=case_has_gt,
                case_gt_total=case_gt_total,
                k_list=k_list,
                rows_by_case=dropped_by_case,
                rank_fn=rank_fn,
            )

        util = tool_utility_by_tool.get(str(tool), {})
        cc = tool_cluster_counts.get(str(tool), {})

        tool_marginal_rows.extend(
            _build_tool_marginal_rows_for_tool(
                sid=sid,
                tool=str(tool),
                strategies=list(strategies_marginal.keys()),
                k_list=k_list,
                full_totals=full_totals,
                drop_totals=drop_totals,
                util=util,
                cluster_counts=cc,
            )
        )

    strat_order = {
        name: idx for idx, name in enumerate(["baseline", "agreement", "calibrated"], start=1)
    }
    tool_marginal_rows.sort(
        key=lambda r: (
            str(r.get("tool") or ""),
            int(strat_order.get(str(r.get("strategy") or ""), 99)),
            int(r.get("k") or 0),
        )
    )

    return tool_marginal_rows
