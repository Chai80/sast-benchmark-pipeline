"""pipeline.analysis.io_utils

Tiny filesystem helpers shared by analysis stages.

Why this exists
---------------
Many stages are intentionally standalone CLIs, but without a shared DB we rely on
JSON/CSV artifacts. These helpers keep I/O consistent and avoid copy/paste drift.

Design goals:
- dependency-free (stdlib only)
- tolerant of minor schema differences (best-effort)
- deterministic output ordering (as much as practical)
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence


def load_json(path: Path) -> Dict[str, Any]:
    """Load a JSON file, returning {} for non-object roots (best-effort)."""
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def write_json(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False), encoding="utf-8")


def as_list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


def write_csv(rows: Sequence[Mapping[str, Any]], path: Path, *, fieldnames: Optional[List[str]] = None) -> None:
    """Write a CSV file from dict rows.

    If fieldnames is None, we compute a deterministic union of keys in insertion
    order of first-seen keys.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    if fieldnames is None:
        seen: set[str] = set()
        cols: List[str] = []
        for r in rows:
            for k in r.keys():
                if k not in seen:
                    seen.add(k)
                    cols.append(k)
        fieldnames = cols

    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in fieldnames})
