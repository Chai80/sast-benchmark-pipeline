"""pipeline.analysis.suite.triage_calibration.core

Lightweight primitives for triage calibration:
- schema constants + public dataclass
- small parsing helpers
- small math helpers
- reading calibration artifacts

Kept dependency-light so both calibration consumers (triage_queue scoring,
triage_eval) and the builder can import it without circular dependencies.
"""

from __future__ import annotations

import csv
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional


TRIAGE_CALIBRATION_SCHEMA_V1: str = "triage_calibration_v1"
TRIAGE_CALIBRATION_SCHEMA_VERSION: str = "triage_calibration_v2"

# Backwards compatible reader (we still accept v1 files).
TRIAGE_CALIBRATION_SUPPORTED_VERSIONS: set[str] = {
    TRIAGE_CALIBRATION_SCHEMA_V1,
    TRIAGE_CALIBRATION_SCHEMA_VERSION,
}


@dataclass(frozen=True)
class CalibrationParamsV1:
    """Parameter bundle for v1-style triage calibration."""

    # Smoothing
    alpha: float = 1.0
    beta: float = 1.0

    # Clamp for log-odds
    p_min: float = 0.01
    p_max: float = 0.99

    # Scoring params (stored in calibration json and used by triage_score_v1)
    agreement_lambda: float = 0.50
    severity_bonus: Mapping[str, float] = None  # type: ignore[assignment]

    # Per-OWASP selection guardrail
    min_support_by_owasp: int = 10

    def __post_init__(self) -> None:
        if self.severity_bonus is None:
            object.__setattr__(
                self,
                "severity_bonus",
                {
                    "HIGH": 0.25,
                    "MEDIUM": 0.10,
                    "LOW": 0.00,
                    "UNKNOWN": 0.00,
                },
            )


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


def _clamp(p: float, lo: float, hi: float) -> float:
    return max(float(lo), min(float(hi), float(p)))


def smoothed_precision(tp: int, fp: int, *, alpha: float, beta: float) -> float:
    denom = float(tp + fp) + float(alpha) + float(beta)
    if denom <= 0:
        return 0.5
    return (float(tp) + float(alpha)) / denom


def log_odds(p: float, *, p_min: float, p_max: float) -> float:
    pp = _clamp(float(p), float(p_min), float(p_max))
    return math.log(pp / (1.0 - pp))


def load_triage_calibration(path: Path) -> Optional[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return None
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return None
    sv = str(data.get("schema_version") or "")
    if sv not in TRIAGE_CALIBRATION_SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported triage calibration schema_version: {data.get('schema_version')}")
    return data


def _load_csv_rows(path: Path) -> List[Dict[str, str]]:
    with Path(path).open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [dict(r) for r in reader if isinstance(r, dict)]


__all__ = [
    "TRIAGE_CALIBRATION_SCHEMA_V1",
    "TRIAGE_CALIBRATION_SCHEMA_VERSION",
    "TRIAGE_CALIBRATION_SUPPORTED_VERSIONS",
    "CalibrationParamsV1",
    "smoothed_precision",
    "log_odds",
    "load_triage_calibration",
]
