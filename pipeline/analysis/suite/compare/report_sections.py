"""pipeline.analysis.suite.compare.report_sections

Section emitters for the suite-to-suite comparison CSV.

The public entrypoint lives in :mod:`.report`; this module contains the
deterministic helpers that append rows for each report section.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .diff import _delta, _to_int


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


def _append_policy_diff(
    rows: List[Dict[str, Any]], *, pol_a: Mapping[str, Any], pol_b: Mapping[str, Any]
) -> None:
    pol_fields = [
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

    _append_row(
        rows,
        section="policy",
        name="auto.warnings",
        a_val=json.dumps(_pol_get(pol_a, ("auto", "warnings")) or []),
        b_val=json.dumps(_pol_get(pol_b, ("auto", "warnings")) or []),
        delta_val=None,
    )


def _append_scanner_config_diff(
    rows: List[Dict[str, Any]], *, sc_a: Mapping[str, Any], sc_b: Mapping[str, Any]
) -> None:
    for key in ("profile", "profile_mode"):
        _append_row(
            rows,
            section="scanner_config",
            name=key,
            a_val=sc_a.get(key),
            b_val=sc_b.get(key),
        )

    _append_row(
        rows,
        section="scanner_config",
        name="missing_tools",
        a_val=json.dumps(sc_a.get("missing_tools") or []),
        b_val=json.dumps(sc_b.get("missing_tools") or []),
        delta_val=None,
    )

    hashes_a = sc_a.get("config_receipt_hashes") if isinstance(sc_a.get("config_receipt_hashes"), Mapping) else {}
    hashes_b = sc_b.get("config_receipt_hashes") if isinstance(sc_b.get("config_receipt_hashes"), Mapping) else {}
    for t in sorted(set(list(hashes_a.keys()) + list(hashes_b.keys()))):
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
        _append_row(rows, section="dataset", name=key, a_val=va, b_val=vb, delta_val=_delta(va, vb))


def _append_eval_diff(
    rows: List[Dict[str, Any]], *, eval_a: Mapping[str, Any], eval_b: Mapping[str, Any]
) -> None:
    for agg in ("micro", "macro"):
        obj_a = eval_a.get(agg) if isinstance(eval_a, dict) else {}
        obj_b = eval_b.get(agg) if isinstance(eval_b, dict) else {}
        strat_keys = sorted(set(list(obj_a.keys()) + list(obj_b.keys())), key=_strategy_order)

        for strat in strat_keys:
            ka_obj = obj_a.get(strat) if isinstance(obj_a, dict) else {}
            kb_obj = obj_b.get(strat) if isinstance(obj_b, dict) else {}

            ks: set[str] = set()
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
    for t in sorted(set(list(cal_w_a.keys()) + list(cal_w_b.keys()))):
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
    for oid in sorted(set(list(cal_by_owasp_a.keys()) + list(cal_by_owasp_b.keys()))):
        wa_map = cal_by_owasp_a.get(oid, {})
        wb_map = cal_by_owasp_b.get(oid, {})
        for t in sorted(set(list(wa_map.keys()) + list(wb_map.keys()))):
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
    for t in sorted(set(list(util_a.keys()) + list(util_b.keys()))):
        ra = util_a.get(t, {})
        rb = util_b.get(t, {})
        for field in ("gt_ids_covered", "unique_gt_ids", "neg_clusters", "exclusive_neg_clusters"):
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


__all__ = [
    "_append_row",
    "_append_policy_diff",
    "_append_scanner_config_diff",
    "_append_dataset_counts",
    "_append_eval_diff",
    "_append_calibration_global",
    "_append_calibration_by_owasp",
    "_append_tool_utility_diff",
    "_append_tool_marginal_diff",
]
