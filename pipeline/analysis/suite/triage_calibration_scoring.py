"""pipeline.analysis.suite.triage_calibration_scoring

Scoring helpers based on a triage calibration artifact.

The scoring functions are used by:
- per-case triage queue generation when a calibration file exists
- suite triage evaluation strategies

They are intentionally small and import only lightweight helpers.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .triage_calibration_utils import _parse_tools_any, _to_int
from .triage_calibration_weights import tool_weights_for_owasp


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
    "triage_score_v1",
    "triage_score_v1_for_row",
]
