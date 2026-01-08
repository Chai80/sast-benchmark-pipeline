from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence


def write_json(path: Path, data: Any, *, indent: int = 2) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=indent), encoding="utf-8")
    return p


def write_csv(
    path: Path,
    rows: Iterable[Dict[str, Any]],
    *,
    fieldnames: Optional[Sequence[str]] = None,
) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    rows_list: List[Dict[str, Any]] = list(rows)

    if fieldnames is None:
        # Stable order: union of keys in first-seen order.
        seen: set[str] = set()
        fields: List[str] = []
        for r in rows_list:
            for k in r.keys():
                if k not in seen:
                    seen.add(k)
                    fields.append(k)
        fieldnames = fields

    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(fieldnames))
        w.writeheader()
        for r in rows_list:
            w.writerow({k: r.get(k, "") for k in fieldnames})

    return p
