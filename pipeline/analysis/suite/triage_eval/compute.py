"""pipeline.analysis.suite.triage_eval.compute

Computation for suite-level triage evaluation.

The intent of this module is to keep metric computation (mostly pure-ish
transformations of in-memory rows) separate from:

- loading inputs (CSV/JSON on disk)
- writing artifacts (CSV/JSON/MD)

This makes the core logic easier to test and easier to follow.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from .metrics import _gt_ids_for_row, _load_case_gt_ids, _to_int, _tools_for_row


RankFn = Callable[[List[Dict[str, str]]], List[Dict[str, str]]]


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

        prec_delta = (strat_prec - base_prec) if (base_prec is not None and strat_prec is not None) else None
        cov_delta = (strat_cov - base_cov) if (base_cov is not None and strat_cov is not None) else None

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

    out.sort(key=lambda r: (str(r.get("case_id") or ""), str(r.get("strategy") or ""), int(r.get("k") or 0)))
    return out


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
                "gt_coverage": None if total_gt == 0 else round(float(covered) / float(total_gt), 6),
                "gt_covered_at_k": int(covered),
                "gt_total": int(total_gt),
            }

    return macro, micro


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

    counts = _parse_tool_counts_json(str(row.get('tool_counts_json') or ''), tools)
    counts.pop(tool, None)
    counts = {k: int(v) for k, v in counts.items() if int(v) > 0}
    if not counts:
        return None

    rr = dict(row)
    new_tools = sorted(counts.keys())

    rr['tool_counts_json'] = _stable_tool_counts_json(counts)
    rr['tools_json'] = json.dumps(new_tools, ensure_ascii=False)
    rr['tools'] = ','.join(new_tools)
    rr['tool_count'] = str(int(len(new_tools)))
    rr['finding_count'] = str(int(sum(int(v) for v in counts.values())))

    # Force re-score under calibrated ranking.
    if 'triage_score_v1' in rr:
        rr['triage_score_v1'] = ''

    return rr


def _build_marginal_strategies(cal: Optional[Dict[str, Any]]) -> Dict[str, RankFn]:
    """Strategies used for drop-one marginal value tables."""

    # Local import avoids pulling strategy code into import-time side effects.
    from .strategies import _rank_agreement, _rank_baseline, _rank_calibrated

    strategies_marginal: Dict[str, RankFn] = {
        'baseline': (lambda rows: _rank_baseline(rows, use_triage_rank=False)),
        'agreement': _rank_agreement,
    }

    if cal:

        def _rank_cal_m(rows: List[Dict[str, str]], *, _cal: Dict[str, Any] = cal) -> List[Dict[str, str]]:
            return _rank_calibrated(rows, cal=_cal)

        strategies_marginal['calibrated'] = _rank_cal_m

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
        int(k): {'tp': 0, 'denom': 0, 'covered': 0, 'gt_total': 0, 'neg': 0} for k in k_list
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

            tp = sum(1 for r in top if _to_int(r.get('gt_overlap'), 0) == 1)
            neg = sum(1 for r in top if _to_int(r.get('gt_overlap'), 0) == 0)

            covered_ids: Set[str] = set()
            if gt_total > 0:
                for r in top:
                    covered_ids.update(_gt_ids_for_row(r))
            covered = int(len(covered_ids)) if gt_total > 0 else 0

            out[kk]['tp'] += int(tp)
            out[kk]['denom'] += int(k_eff)
            out[kk]['neg'] += int(neg)
            if gt_total > 0:
                out[kk]['covered'] += int(covered)
                out[kk]['gt_total'] += int(gt_total)

    return out


def _metrics_from_totals(t: Mapping[str, int]) -> Dict[str, Any]:
    denom = int(t.get('denom', 0) or 0)
    gt_total = int(t.get('gt_total', 0) or 0)
    tp = int(t.get('tp', 0) or 0)
    covered = int(t.get('covered', 0) or 0)
    neg = int(t.get('neg', 0) or 0)
    return {
        'precision': None if denom == 0 else float(tp) / float(denom),
        'gt_coverage': None if gt_total == 0 else float(covered) / float(gt_total),
        'neg_in_topk': int(neg),
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
            'clusters_with_tool': 0,
            'clusters_exclusive_total': 0,
            'clusters_exclusive_pos': 0,
            'clusters_exclusive_neg': 0,
        }
        for t in all_tools
    }

    for cid in case_ids:
        if not case_has_gt.get(cid, False):
            continue
        for r in (by_case.get(cid) or []):
            tools = _tools_for_row(r)
            if not tools:
                continue

            for t in tools:
                tt = str(t)
                if tt not in out:
                    out[tt] = {
                        'clusters_with_tool': 0,
                        'clusters_exclusive_total': 0,
                        'clusters_exclusive_pos': 0,
                        'clusters_exclusive_neg': 0,
                    }
                out[tt]['clusters_with_tool'] += 1

            if len(tools) == 1:
                tt = str(tools[0])
                if tt not in out:
                    out[tt] = {
                        'clusters_with_tool': 0,
                        'clusters_exclusive_total': 0,
                        'clusters_exclusive_pos': 0,
                        'clusters_exclusive_neg': 0,
                    }

                out[tt]['clusters_exclusive_total'] += 1
                if _to_int(r.get('gt_overlap'), 0) == 1:
                    out[tt]['clusters_exclusive_pos'] += 1
                else:
                    out[tt]['clusters_exclusive_neg'] += 1

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

            p_full = full_m.get('precision')
            p_drop = drop_m.get('precision')
            c_full = full_m.get('gt_coverage')
            c_drop = drop_m.get('gt_coverage')

            dp = (float(p_drop) - float(p_full)) if (p_full is not None and p_drop is not None) else None
            dc = (float(c_drop) - float(c_full)) if (c_full is not None and c_drop is not None) else None

            neg_full = int(full_m.get('neg_in_topk') or 0)
            neg_drop = int(drop_m.get('neg_in_topk') or 0)

            rows.append(
                {
                    'suite_id': sid,
                    'tool': str(tool),
                    'strategy': str(strat),
                    'k': int(kk),
                    'precision_full': '' if p_full is None else round(float(p_full), 6),
                    'precision_drop': '' if p_drop is None else round(float(p_drop), 6),
                    'delta_precision': '' if dp is None else round(float(dp), 6),
                    'gt_coverage_full': '' if c_full is None else round(float(c_full), 6),
                    'gt_coverage_drop': '' if c_drop is None else round(float(c_drop), 6),
                    'delta_gt_coverage': '' if dc is None else round(float(dc), 6),
                    'neg_in_topk_full': int(neg_full),
                    'neg_in_topk_drop': int(neg_drop),
                    'delta_neg_in_topk': int(neg_drop) - int(neg_full),
                    'gt_ids_covered': int(util.get('gt_ids_covered') or 0),
                    'unique_gt_ids': int(util.get('unique_gt_ids') or 0),
                    'neg_clusters': int(util.get('neg_clusters') or 0),
                    'exclusive_neg_clusters': int(util.get('exclusive_neg_clusters') or 0),
                    'clusters_with_tool': int(cluster_counts.get('clusters_with_tool') or 0),
                    'clusters_exclusive_total': int(cluster_counts.get('clusters_exclusive_total') or 0),
                    'clusters_exclusive_pos': int(cluster_counts.get('clusters_exclusive_pos') or 0),
                    'clusters_exclusive_neg': int(cluster_counts.get('clusters_exclusive_neg') or 0),
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

    tool_utility_by_tool: Dict[str, Dict[str, Any]] = {str(r.get('tool') or ''): dict(r) for r in tool_rows}

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
        dropped_by_case = _drop_tool_by_case(by_case=by_case, tool=str(tool), case_ids=case_ids, case_has_gt=case_has_gt)

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

    strat_order = {name: idx for idx, name in enumerate(['baseline', 'agreement', 'calibrated'], start=1)}
    tool_marginal_rows.sort(
        key=lambda r: (
            str(r.get('tool') or ''),
            int(strat_order.get(str(r.get('strategy') or ''), 99)),
            int(r.get('k') or 0),
        )
    )

    return tool_marginal_rows


def _compute_topk_focus(
    *,
    k_list: Sequence[int],
    strategies: Sequence[str],
    macro: Dict[str, Dict[str, Dict[str, Any]]],
    micro: Dict[str, Dict[str, Dict[str, Any]]],
) -> Dict[str, Any]:
    focus_ks = [k for k in (10, 25, 50) if k in k_list]
    focus_strategies = [s for s in ("baseline", "calibrated_global", "calibrated") if s in strategies]

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


def _compute_calibration_context(cal: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not cal or not isinstance(cal, dict):
        return None

    scoring = cal.get("scoring") if isinstance(cal.get("scoring"), dict) else {}
    min_support_by_owasp = int(scoring.get("min_support_by_owasp", 10))

    fallback: List[str] = []
    by_owasp = cal.get("tool_stats_by_owasp") if isinstance(cal.get("tool_stats_by_owasp"), dict) else {}
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

    macro_prec_sum: Dict[str, Dict[int, float]] = defaultdict(lambda: defaultdict(float))
    macro_prec_n: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    micro_prec_tp: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    micro_prec_denom: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))

    macro_cov_sum: Dict[str, Dict[int, float]] = defaultdict(lambda: defaultdict(float))
    macro_cov_n: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    micro_cov_covered: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    micro_cov_total: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))

    gt_cover_tools: Dict[str, Set[str]] = defaultdict(set)
    tool_neg_clusters: Dict[str, int] = defaultdict(int)
    tool_excl_neg_clusters: Dict[str, int] = defaultdict(int)

    # --- Per-case eval -------------------------------------------------
    for case_id in case_ids:
        case_rows = list(by_case.get(case_id) or [])
        n_clusters = len(case_rows)
        if n_clusters == 0:
            cases_no_clusters.append(case_id)

        gt_ids, has_gt = _load_case_gt_ids(Path(cases_dir) / case_id)
        gt_total = len(gt_ids)
        if has_gt:
            cases_with_gt.append(case_id)
        else:
            cases_without_gt.append(case_id)

        case_has_gt[case_id] = bool(has_gt)
        case_gt_total[case_id] = int(gt_total)

        if has_gt and n_clusters == 0:
            cases_with_gt_but_no_clusters.append(case_id)

        if has_gt and n_clusters > 0:
            any_pos = any(_to_int(r.get("gt_overlap"), 0) == 1 for r in case_rows)
            if not any_pos:
                cases_with_gt_but_no_overlaps.append(case_id)

        for strat, rank_fn in strategies.items():
            ordered = rank_fn(case_rows)

            if max_k > 0 and ordered:
                covered_so_far: Set[str] = set()
                max_rank = min(int(max_k), len(ordered))
                for idx, r in enumerate(ordered[:max_rank], start=1):
                    ids = _gt_ids_for_row(r) if has_gt else []
                    if has_gt and gt_total:
                        covered_so_far.update(ids)
                        cum_cov: Optional[float] = float(len(covered_so_far)) / float(gt_total)
                    else:
                        cum_cov = None

                    topk_rows.append(
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

            for k in k_list:
                k_eff = min(k, len(ordered))
                top = ordered[:k_eff]

                tp = sum(1 for r in top if _to_int(r.get("gt_overlap"), 0) == 1) if has_gt else 0
                denom = int(k_eff) if has_gt else 0
                prec = (float(tp) / float(denom)) if denom else None

                covered_ids: Set[str] = set()
                if has_gt and gt_total:
                    for r in top:
                        covered_ids.update(_gt_ids_for_row(r))
                covered = len(covered_ids) if (has_gt and gt_total) else 0
                cov = (float(covered) / float(gt_total)) if (has_gt and gt_total) else None

                by_case_rows.append(
                    {
                        "suite_id": sid,
                        "case_id": case_id,
                        "strategy": strat,
                        "k": int(k),
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
                    macro_prec_sum[strat][k] += float(tp) / float(denom)
                    macro_prec_n[strat][k] += 1
                    micro_prec_tp[strat][k] += int(tp)
                    micro_prec_denom[strat][k] += int(denom)

                if has_gt and gt_total:
                    macro_cov_sum[strat][k] += float(covered) / float(gt_total)
                    macro_cov_n[strat][k] += 1
                    micro_cov_covered[strat][k] += int(covered)
                    micro_cov_total[strat][k] += int(gt_total)

        if has_gt:
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

    deltas_rows = _compute_deltas_by_case(sid=sid, by_case_rows=by_case_rows)

    macro, micro = _compute_macro_micro(
        strategies=list(strategies.keys()),
        k_list=k_list,
        macro_prec_sum=macro_prec_sum,
        macro_prec_n=macro_prec_n,
        micro_prec_tp=micro_prec_tp,
        micro_prec_denom=micro_prec_denom,
        macro_cov_sum=macro_cov_sum,
        macro_cov_n=macro_cov_n,
        micro_cov_covered=micro_cov_covered,
        micro_cov_total=micro_cov_total,
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
