"""pipeline.analysis.suite.compare.diff

Small helpers for suite-to-suite comparison.

Kept intentionally small and deterministic.
"""

from __future__ import annotations

from typing import Any, Optional


def _to_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return int(default)
        if isinstance(x, bool):
            return int(x)
        return int(float(str(x)))
    except Exception:
        return int(default)


def _to_float(x: Any, default: Optional[float] = None) -> Optional[float]:
    try:
        if x is None:
            return default
        s = str(x).strip()
        if s == "":
            return default
        return float(s)
    except Exception:
        return default


def _delta(a: Any, b: Any) -> Optional[float]:
    aa = _to_float(a, None)
    bb = _to_float(b, None)
    if aa is None or bb is None:
        return None
    return float(bb) - float(aa)
