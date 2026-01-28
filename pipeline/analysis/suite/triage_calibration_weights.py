"""pipeline.analysis.suite.triage_calibration_weights

Helpers for reading tool weights from a triage calibration JSON.

These functions are used by:
- per-case triage queue scoring
- triage evaluation strategies

They intentionally avoid importing the calibration builder to keep dependency
edges simple.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from .triage_calibration_utils import _normalize_owasp_id


def tool_weights_from_calibration(cal: Mapping[str, Any]) -> Dict[str, float]:
    out: Dict[str, float] = {}
    rows = cal.get("tool_stats_global") or cal.get("tool_stats") or []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        t = str(row.get("tool") or "").strip()
        if not t:
            continue
        try:
            out[t] = float(row.get("weight"))
        except Exception:
            out[t] = 0.0
    return out


def tool_weights_for_owasp(
    cal: Mapping[str, Any],
    *,
    owasp_id: Optional[str],
    min_support: int = 10,
) -> Dict[str, float]:
    """Return tool weights for a specific OWASP category with fallback.

    Rules
    -----
    - If the calibration JSON contains a slice for `owasp_id` and that slice has
      at least `min_support` GT-scored clusters, return that slice's weights.
    - Otherwise, fall back to global weights.

    This function is intentionally small and dependency-free so both:
      - per-case triage_queue scoring, and
      - suite_triage_eval "calibrated" strategy
    can use the exact same selection logic.
    """

    global_weights = tool_weights_from_calibration(cal)
    oid = _normalize_owasp_id(owasp_id)
    if not oid:
        return global_weights

    by_owasp = cal.get("tool_stats_by_owasp") if isinstance(cal, dict) else None
    if not isinstance(by_owasp, dict):
        return global_weights

    slice_obj = by_owasp.get(oid)
    if slice_obj is None:
        return global_weights

    # v2 shape: { support: {clusters, cases, ...}, tool_stats: [...] }
    if isinstance(slice_obj, dict):
        support = slice_obj.get("support")
        clusters = 0
        if isinstance(support, dict):
            try:
                clusters = int(support.get("clusters") or 0)
            except Exception:
                clusters = 0
        tool_stats = slice_obj.get("tool_stats")
        if not isinstance(tool_stats, list):
            tool_stats = []

        if clusters < int(min_support):
            return global_weights

        out: Dict[str, float] = {}
        for row in tool_stats:
            if not isinstance(row, dict):
                continue
            t = str(row.get("tool") or "").strip()
            if not t:
                continue
            try:
                out[t] = float(row.get("weight"))
            except Exception:
                out[t] = 0.0

        return out or global_weights

    # Legacy/experimental shape: directly a list of tool_stat dicts
    if isinstance(slice_obj, list):
        # No support count available -> conservative fallback.
        return global_weights

    return global_weights


__all__ = [
    "tool_weights_from_calibration",
    "tool_weights_for_owasp",
]
