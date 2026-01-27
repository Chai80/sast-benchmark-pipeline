"""Tool-centric triage-eval computations.

Extracted from `compute.py` to keep the main module smaller and easier to scan.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from .metrics import _gt_ids_for_row, _to_int, _tools_for_row


RankFn = Callable[[List[Dict[str, str]]], List[Dict[str, str]]]


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


def _stable_tool_counts_json(counts: Dict[str, int]) -> str:
    """Deterministic JSON encoding for tool-count dicts."""

    return json.dumps({k: int(v) for k, v in sorted(counts.items())}, sort_keys=True)


def _parse_tool_counts_json(raw: str, fallback_tools: Sequence[str]) -> Dict[str, int]:
    """Parse tool_counts_json, falling back to 1-per-tool from tools list."""

    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                out: Dict[str, int] = {}
                for k, v in obj.items():
                    kk = str(k).strip()
                    if not kk:
                        continue
                    out[kk] = _to_int(v, 0)
                out = {k: int(v) for k, v in out.items() if int(v) > 0}
                if out:
                    return out
        except Exception:
            pass

    return {t: 1 for t in sorted(set(str(x) for x in fallback_tools if str(x).strip()))}


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


def _build_marginal_strategies(cal: Optional[Dict[str, Any]]) -> Dict[str, RankFn]:
    """Strategies used for drop-one marginal value tables."""

    # Local import avoids pulling strategy code into import-time side effects.
    from .strategies import _rank_agreement, _rank_baseline, _rank_calibrated

    strategies_marginal: Dict[str, RankFn] = {
        "baseline": (lambda rows: _rank_baseline(rows, use_triage_rank=False)),
        "agreement": _rank_agreement,
    }

    if cal:

        def _rank_cal_m(
            rows: List[Dict[str, str]], *, _cal: Dict[str, Any] = cal
        ) -> List[Dict[str, str]]:
            return _rank_calibrated(rows, cal=_cal)

        strategies_marginal["calibrated"] = _rank_cal_m

    return strategies_marginal


def _micro_totals_for_rows(
    *,
    case_ids: Sequence[str],
    case_has_gt: Dict[str, bool],
    case_gt_total: Dict[str, int],
    k_list: Sequence[int],
    rows_by_case: Dict[str, List[Dict[str, str]]],
    rank_fn: RankFn,
) -> Dict[int, Dict[str, int]]:
    """Micro totals used for marginal value comparison (precision/coverage/neg)."""

    out: Dict[int, Dict[str, int]] = {
        int(k): {"tp": 0, "denom": 0, "covered": 0, "gt_total": 0, "neg": 0} for k in k_list
    }

    for cid in case_ids:
        if not case_has_gt.get(cid, False):
            continue
        gt_total = int(case_gt_total.get(cid, 0) or 0)

        case_rows = list(rows_by_case.get(cid) or [])
        ordered = rank_fn(case_rows) if case_rows else []

        for k in k_list:
            kk = int(k)
            k_eff = min(kk, len(ordered))
            top = ordered[:k_eff]

            tp = sum(1 for r in top if _to_int(r.get("gt_overlap"), 0) == 1)
            neg = sum(1 for r in top if _to_int(r.get("gt_overlap"), 0) == 0)

            covered_ids: Set[str] = set()
            if gt_total > 0:
                for r in top:
                    covered_ids.update(_gt_ids_for_row(r))
            covered = int(len(covered_ids)) if gt_total > 0 else 0

            out[kk]["tp"] += int(tp)
            out[kk]["denom"] += int(k_eff)
            out[kk]["neg"] += int(neg)
            if gt_total > 0:
                out[kk]["covered"] += int(covered)
                out[kk]["gt_total"] += int(gt_total)

    return out


def _metrics_from_totals(t: Mapping[str, int]) -> Dict[str, Any]:
    denom = int(t.get("denom", 0) or 0)
    gt_total = int(t.get("gt_total", 0) or 0)
    tp = int(t.get("tp", 0) or 0)
    covered = int(t.get("covered", 0) or 0)
    neg = int(t.get("neg", 0) or 0)
    return {
        "precision": None if denom == 0 else float(tp) / float(denom),
        "gt_coverage": None if gt_total == 0 else float(covered) / float(gt_total),
        "neg_in_topk": int(neg),
    }


def _compute_tool_cluster_counts(
    *,
    all_tools: Sequence[str],
    case_ids: Sequence[str],
    by_case: Dict[str, List[Dict[str, str]]],
    case_has_gt: Dict[str, bool],
) -> Dict[str, Dict[str, int]]:
    """Counts used to contextualize marginal value rows."""

    # Pre-seed keys so missing tools still appear with zeros.
    out: Dict[str, Dict[str, int]] = {
        str(t): {
            "clusters_with_tool": 0,
            "clusters_exclusive_total": 0,
            "clusters_exclusive_pos": 0,
            "clusters_exclusive_neg": 0,
        }
        for t in all_tools
    }

    for cid in case_ids:
        if not case_has_gt.get(cid, False):
            continue
        for r in by_case.get(cid) or []:
            tools = _tools_for_row(r)
            if not tools:
                continue

            for t in tools:
                tt = str(t)
                if tt not in out:
                    out[tt] = {
                        "clusters_with_tool": 0,
                        "clusters_exclusive_total": 0,
                        "clusters_exclusive_pos": 0,
                        "clusters_exclusive_neg": 0,
                    }
                out[tt]["clusters_with_tool"] += 1

            if len(tools) == 1:
                tt = str(tools[0])
                if tt not in out:
                    out[tt] = {
                        "clusters_with_tool": 0,
                        "clusters_exclusive_total": 0,
                        "clusters_exclusive_pos": 0,
                        "clusters_exclusive_neg": 0,
                    }

                out[tt]["clusters_exclusive_total"] += 1
                if _to_int(r.get("gt_overlap"), 0) == 1:
                    out[tt]["clusters_exclusive_pos"] += 1
                else:
                    out[tt]["clusters_exclusive_neg"] += 1

    # Normalize types
    for t, d in out.items():
        out[t] = {k: int(v) for k, v in d.items()}

    return out


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
