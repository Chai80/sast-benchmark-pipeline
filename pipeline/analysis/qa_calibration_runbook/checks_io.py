from __future__ import annotations

"""pipeline.analysis.qa_calibration_runbook.checks_io

Shared I/O helpers for the QA calibration checklist.

This module exists so the checklist implementation can be split across
submodules without duplicating low-level CSV/JSON parsing boilerplate.
"""

import csv
import json
from pathlib import Path
from typing import Any, Dict, List


def _read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _read_csv_header(path: Path) -> List[str]:
    p = Path(path)
    with p.open("r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, [])
    return [str(h).strip() for h in (header or []) if str(h).strip()]


def _read_csv_dict_rows(path: Path) -> List[Dict[str, str]]:
    p = Path(path)
    with p.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [dict(r) for r in reader if isinstance(r, dict)]


def _parse_json_list(raw: str) -> List[str]:
    s = str(raw or "").strip()
    if not s:
        return []
    try:
        v = json.loads(s)
        if isinstance(v, list):
            return [str(x) for x in v if str(x).strip()]
    except Exception:
        return []
    return []


def _to_int(x: Any, default: int = 0) -> int:
    """Best-effort int parsing for checklist validation.

    Accepts strings, floats, ints; returns default on failure.
    """

    try:
        if x is None:
            return int(default)
        if isinstance(x, bool):
            return int(x)
        return int(float(str(x)))
    except Exception:
        return int(default)


def _csv_has_any_nonempty_value(path: Path, *, column: str) -> bool:
    """Return True if *any* row has a non-empty value in the given column."""

    p = Path(path)
    with p.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or (column not in reader.fieldnames):
            return False
        for row in reader:
            v = row.get(column)
            if v is None:
                continue
            if str(v).strip() != "":
                return True
    return False
