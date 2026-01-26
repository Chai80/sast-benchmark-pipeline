"""sast_benchmark.io.fs

Atomic, stable filesystem writers.

Why this module exists
----------------------
Over time, it's easy for multiple parts of the pipeline to grow their own
"write_json" helpers. That leads to subtle drift (different indentation,
key ordering, newline conventions, or non-atomic writes), which makes artifacts
noisy to diff and can break downstream stages if a process is interrupted
mid-write.

This module centralizes atomic writes for JSON / text / CSV so other modules
can import a single, dependency-safe implementation.
"""

from __future__ import annotations

import csv
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence


def _atomic_write_text(
    path: Path,
    write_fn,
    *,
    encoding: str = "utf-8",
    newline: Optional[str] = None,
) -> None:
    """Write a file atomically by writing to a temp file and os.replace()."""

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(prefix=f"{p.name}.", suffix=".tmp", dir=str(p.parent))
    tmp_path = Path(tmp_name)

    try:
        with os.fdopen(fd, "w", encoding=encoding, newline=newline) as f:
            write_fn(f)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, p)
    finally:
        # If os.replace fails, best-effort cleanup of the temp file.
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass


def write_text_atomic(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write UTF-8 text atomically."""

    def _write(f) -> None:
        f.write(text)

    _atomic_write_text(Path(path), _write, encoding=encoding)


def write_json_atomic(
    path: Path,
    data: Any,
    *,
    indent: int = 2,
    sort_keys: bool = True,
    ensure_ascii: bool = False,
    encoding: str = "utf-8",
) -> None:
    """Write JSON atomically with stable formatting."""

    def _write(f) -> None:
        json.dump(data, f, indent=indent, sort_keys=sort_keys, ensure_ascii=ensure_ascii)
        f.write("\n")

    _atomic_write_text(Path(path), _write, encoding=encoding)


def read_json(path: Path, *, encoding: str = "utf-8") -> Any:
    """Read JSON from disk."""

    with Path(path).open("r", encoding=encoding) as f:
        return json.load(f)


def write_csv_atomic(
    path: Path,
    rows: Iterable[Mapping[str, Any]],
    *,
    fieldnames: Optional[Sequence[str]] = None,
    encoding: str = "utf-8",
) -> None:
    """Write CSV atomically.

    If *fieldnames* is not provided, a stable header order is derived from the
    first-seen order of keys across rows.
    """

    rows_list = [dict(r) for r in rows]

    if fieldnames is None:
        seen: set[str] = set()
        fields: list[str] = []
        for r in rows_list:
            for k in r.keys():
                if k not in seen:
                    seen.add(k)
                    fields.append(k)
        fieldnames = fields

    # DictWriter expects a concrete list.
    fns = list(fieldnames)

    def _write(f) -> None:
        w = csv.DictWriter(f, fieldnames=fns)
        w.writeheader()
        for r in rows_list:
            w.writerow({k: r.get(k, "") for k in fns})

    # newline="" is the recommended way to write CSV files.
    _atomic_write_text(Path(path), _write, encoding=encoding, newline="")
