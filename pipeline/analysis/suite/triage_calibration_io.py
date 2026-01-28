"""pipeline.analysis.suite.triage_calibration_io

Filesystem I/O helpers for triage calibration.

Separated from the builder so consumers can load a calibration file without
pulling in the full build implementation.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .triage_calibration_types import TRIAGE_CALIBRATION_SUPPORTED_VERSIONS


def load_triage_calibration(path: Path) -> Optional[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return None
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return None
    sv = str(data.get("schema_version") or "")
    if sv not in TRIAGE_CALIBRATION_SUPPORTED_VERSIONS:
        raise ValueError(
            f"Unsupported triage calibration schema_version: {data.get('schema_version')}"
        )
    return data


def _load_csv_rows(path: Path) -> List[Dict[str, str]]:
    with Path(path).open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [dict(r) for r in reader if isinstance(r, dict)]


__all__ = [
    "load_triage_calibration",
]
