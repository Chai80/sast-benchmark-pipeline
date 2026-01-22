from __future__ import annotations

"""pipeline.analysis.stages.common.severity

Small helpers for reasoning about normalized severity values.

Stages often need a consistent way to:
- rank severities for sorting
- choose the maximum severity within a cluster
"""

from typing import Any, Dict, List, Tuple


def severity_rank(sev: Any) -> int:
    s = str(sev or "").upper().strip()
    if s == "HIGH":
        return 3
    if s == "MEDIUM":
        return 2
    if s == "LOW":
        return 1
    return 0


def max_severity(items: List[Dict[str, Any]]) -> Tuple[str, int]:
    """Return (max_severity_label, numeric_rank) for a list of finding-like dicts."""
    best: Tuple[str, int] = ("", 0)
    for it in items or []:
        r = severity_rank(it.get("severity"))
        if r > best[1]:
            best = (str(it.get("severity") or ""), r)
    return best
