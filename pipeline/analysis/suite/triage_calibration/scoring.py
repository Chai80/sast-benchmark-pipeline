"""pipeline.analysis.suite.triage_calibration.scoring

Tool weight extraction + triage scoring helpers.

Kept lightweight so both per-case triage_queue generation and suite triage_eval
can use the same scoring logic without importing the builder.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Sequence

from .core import _normalize_owasp_id, _parse_tools_any, _to_int


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


def triage_score_v1(
    *,
    tools: Sequence[str],
    tool_count: int,
    max_severity: str,
    tool_weights: Mapping[str, float],
    agreement_lambda: float,
    severity_bonus: Mapping[str, float],
) -> float:
    """Compute calibrated triage score (v1).

    triage_score_v1 = sum(tool weights) + agreement bonus + severity bonus
    """

    base = 0.0
    for t in tools or []:
        tt = str(t).strip()
        if not tt:
            continue
        base += float(tool_weights.get(tt, 0.0))

    agreement_bonus = float(agreement_lambda) * float(max(int(tool_count) - 1, 0))

    sev = str(max_severity or "").strip().upper() or "UNKNOWN"
    sev_bonus = float(severity_bonus.get(sev, severity_bonus.get("UNKNOWN", 0.0)))

    return float(base + agreement_bonus + sev_bonus)


def triage_score_v1_for_row(row: Mapping[str, Any], cal: Mapping[str, Any]) -> float:
    """Row-based scorer for triage_dataset rows."""

    scoring = cal.get("scoring", {}) if isinstance(cal, dict) else {}
    agreement_lambda = float(scoring.get("agreement_lambda", 0.0))
    severity_bonus = scoring.get("severity_bonus")
    if not isinstance(severity_bonus, dict):
        severity_bonus = {"HIGH": 0.25, "MEDIUM": 0.10, "LOW": 0.0, "UNKNOWN": 0.0}

    tools = _parse_tools_any(row.get("tools_json") or row.get("tools") or "")
    tool_count = _to_int(row.get("tool_count"), default=len(tools))

    max_sev = str(row.get("max_severity") or row.get("severity") or "UNKNOWN")

    min_support = int(scoring.get("min_support_by_owasp", 10)) if isinstance(scoring, dict) else 10
    weights = tool_weights_for_owasp(
        cal, owasp_id=str(row.get("owasp_id") or ""), min_support=min_support
    )

    return triage_score_v1(
        tools=tools,
        tool_count=tool_count,
        max_severity=max_sev,
        tool_weights=weights,
        agreement_lambda=agreement_lambda,
        severity_bonus=severity_bonus,
    )


__all__ = [
    "tool_weights_from_calibration",
    "tool_weights_for_owasp",
    "triage_score_v1",
    "triage_score_v1_for_row",
]
