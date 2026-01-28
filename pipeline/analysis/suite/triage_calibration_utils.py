"""pipeline.analysis.suite.triage_calibration_utils

Shared small utilities for triage calibration.

These helpers were originally defined in the monolithic
:mod:`pipeline.analysis.suite.suite_triage_calibration` module and are now kept
here so the implementation can be split without duplicating logic.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return int(default)
        if isinstance(x, bool):
            return int(x)
        return int(float(str(x)))
    except Exception:
        return int(default)


def _round6(x: float) -> float:
    return float(f"{float(x):.6f}")


def _parse_json_list(raw: str) -> List[str]:
    if not raw:
        return []
    try:
        v = json.loads(raw)
        if isinstance(v, list):
            return [str(x) for x in v if str(x).strip()]
    except Exception:
        return []
    return []


def _parse_tools_any(raw: Any) -> List[str]:
    """Parse tools from either tools_json (JSON list) or tools (comma string)."""

    if raw is None:
        return []

    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]

    s = str(raw).strip()
    if not s:
        return []

    # JSON list
    if s.startswith("["):
        tools = _parse_json_list(s)
        if tools:
            return tools

    # Comma-delimited
    return [t.strip() for t in s.split(",") if t.strip()]


_RE_OWASP_ID = re.compile(r"^A(\d{1,2})$", re.IGNORECASE)


def _normalize_owasp_id(v: Any) -> Optional[str]:
    s = str(v or "").strip().upper()
    if not s:
        return None
    m = _RE_OWASP_ID.match(s)
    if not m:
        return None
    n = int(m.group(1))
    if n < 1 or n > 10:
        return None
    return f"A{n:02d}"


__all__ = [
    "_now_iso",
    "_to_int",
    "_round6",
    "_parse_json_list",
    "_parse_tools_any",
    "_normalize_owasp_id",
]
