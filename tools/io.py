#!/usr/bin/env python3
"""tools/io.py

Single source of truth for tiny filesystem helpers used across the pipeline.

Why this file exists
--------------------
Over time, it's easy for multiple modules to grow their own versions of:
  - write_json / read_json
  - read_line_content

That creates a subtle "spaghetti" risk: two helpers with the same name slowly
diverge (different JSON formatting options, different newline handling, etc.),
and different tools start using different behaviors.

To avoid that, keep the actual implementations here and have other modules
import (or re-export) from this module.

Design
------
- This module is intentionally small.
- It contains ONLY filesystem IO (no normalization policy).
- Normalization logic lives in tools/normalize/*.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

# Canonical, dependency-safe IO helpers.
from sast_benchmark.io.fs import (
    read_json as _read_json,
    write_csv_atomic as _write_csv_atomic,
    write_json_atomic as _write_json_atomic,
    write_text_atomic as _write_text_atomic,
)


def write_json(path: Path, data: Any) -> None:
    """Write pretty JSON to disk (UTF-8) using an atomic replace.

    This is a thin wrapper over :func:`sast_benchmark.io.fs.write_json_atomic`.

    The stable formatting (indent + sort_keys) reduces diff noise across runs
    and prevents subtle drift as the repo evolves.
    """

    _write_json_atomic(Path(path), data, indent=2, sort_keys=True, ensure_ascii=False)


def write_json_atomic(
    path: Path,
    data: Any,
    *,
    indent: int = 2,
    sort_keys: bool = True,
    ensure_ascii: bool = False,
) -> None:
    """Explicit atomic JSON writer (canonical API)."""

    _write_json_atomic(
        Path(path), data, indent=indent, sort_keys=sort_keys, ensure_ascii=ensure_ascii
    )


def read_json(path: Path) -> Any:
    """Read JSON from disk (UTF-8)."""

    return _read_json(Path(path))


def write_text_atomic(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write UTF-8 text to disk atomically (canonical API)."""

    _write_text_atomic(Path(path), text, encoding=encoding)


def write_csv_atomic(
    path: Path,
    rows: Any,
    *,
    fieldnames: Optional[list[str]] = None,
) -> None:
    """Write CSV to disk atomically (canonical API)."""

    _write_csv_atomic(Path(path), rows, fieldnames=fieldnames)


def read_line_content(
    repo_path: Path,
    file_path: Optional[str],
    line_no: Optional[int],
) -> Optional[str]:
    """Best-effort read of a 1-indexed line from repo_path/file_path."""
    if not file_path or not line_no:
        return None

    try:
        n = int(line_no)
        if n <= 0:
            return None

        repo_root = repo_path.resolve()
        p = Path(file_path)

        # If the tool reports an absolute path, only allow it if it lives under
        # repo_root. If it's relative, resolve it relative to repo_root.
        abs_path = p.resolve() if p.is_absolute() else (repo_root / p).resolve()

        # Enforce that the resolved path stays within the repo root.
        try:
            abs_path.relative_to(repo_root)
        except ValueError:
            return None

        if not abs_path.exists() or not abs_path.is_file():
            return None

        with abs_path.open("r", encoding="utf-8", errors="replace") as f:
            for i, ln in enumerate(f, start=1):
                if i == n:
                    return ln.rstrip("\n")
    except Exception:
        return None

    return None
