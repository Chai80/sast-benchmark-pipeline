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

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional


def write_json(path: Path, data: Any) -> None:
    """Write pretty JSON to disk (UTF-8) using an atomic replace.

    Why atomic
    ----------
    Manifests like case.json / suite.json / run.json are effectively state.
    If the process is interrupted while writing, a partially-written JSON file
    can break downstream analysis in confusing ways.

    We write to a temporary file in the same directory and then `os.replace`
    it into place so readers never observe a truncated JSON file.
    """

    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, path)
    finally:
        # If os.replace fails, best-effort cleanup of the temp file.
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass


def read_json(path: Path) -> Any:
    """Read JSON from disk (UTF-8)."""
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


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
