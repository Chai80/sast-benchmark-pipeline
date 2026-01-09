"""sast_benchmark.io.run_dir

Run directory / run-id helpers that are part of the **filesystem contract**.

Why this module exists
----------------------
We intentionally keep the canonical "how do we create a new run directory?" logic
in the *contracts* layer (sast_benchmark), so that:

- tools/* (scanner adapters) can depend on it
- pipeline/* (orchestration) can depend on it
- but contracts do NOT depend on tools or pipeline (prevents cycles)

This is one of the key guardrails for keeping the repo non-spaghetti.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple, Union


# Repo root = parent of sast_benchmark/
ROOT_DIR = Path(__file__).resolve().parents[2]


def _anchor_under_root(path: Path) -> Path:
    """Anchor a relative path under the project root."""
    return path if path.is_absolute() else (ROOT_DIR / path)


def create_run_dir(output_root: Path | str) -> tuple[str, Path]:
    """Create a dated run directory like YYYYMMDDNNHHMMSS under output_root.

    - YYYYMMDD   : UTC date
    - NN         : per-day sequence number (01,02,...) computed from existing run dirs
    - HHMMSS     : UTC time (for readability + accidental collision resistance)

    Backwards-compatible: older runs may be named YYYYMMDDNN (10 digits).

    If output_root is relative (e.g. 'runs/semgrep'), it is anchored under ROOT_DIR.
    """
    root = output_root if isinstance(output_root, Path) else Path(output_root)
    root = _anchor_under_root(root)
    root.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    today = now.strftime("%Y%m%d")
    hhmmss = now.strftime("%H%M%S")

    # Existing runs may be 10 digits (YYYYMMDDNN) or 16 digits (YYYYMMDDNNHHMMSS).
    existing_idx: List[int] = []
    for d in root.iterdir():
        if not d.is_dir():
            continue
        name = d.name
        if not name.startswith(today):
            continue
        if len(name) < 10:
            continue
        nn = name[8:10]
        if nn.isdigit():
            existing_idx.append(int(nn))

    idx = (max(existing_idx) if existing_idx else 0) + 1

    # Concurrency-safe creation: if a directory already exists (another process),
    # increment NN and retry.
    while True:
        run_id = f"{today}{idx:02d}{hhmmss}"
        run_dir = root / run_id
        try:
            run_dir.mkdir(parents=True, exist_ok=False)
            return run_id, run_dir
        except FileExistsError:
            idx += 1


def create_run_dir_compat(output_root: Union[str, Path]) -> Tuple[str, Path]:
    """Backwards-compatible alias (historical name used by older code)."""
    run_id, run_dir = create_run_dir(output_root)
    return run_id, run_dir
