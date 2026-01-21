from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence

from sast_benchmark.io.fs import write_csv_atomic, write_json_atomic


def write_json(path: Path, data: Any, *, indent: int = 2) -> Path:
    """Write JSON analysis artifacts.

    This is a thin wrapper over :func:`sast_benchmark.io.fs.write_json_atomic`.
    Returning the written path keeps existing call sites unchanged.
    """

    p = Path(path)
    write_json_atomic(p, data, indent=indent, sort_keys=True, ensure_ascii=False)
    return p


def write_csv(
    path: Path,
    rows: Iterable[Dict[str, Any]],
    *,
    fieldnames: Optional[Sequence[str]] = None,
) -> Path:
    """Write CSV analysis artifacts.

    This is a thin wrapper over :func:`sast_benchmark.io.fs.write_csv_atomic`.
    Returning the written path keeps existing call sites unchanged.
    """

    p = Path(path)
    write_csv_atomic(p, rows, fieldnames=fieldnames)
    return p
