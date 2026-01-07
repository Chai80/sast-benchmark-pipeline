"""pipeline.analysis.run_discovery

Helpers for discovering which *normalized JSON* files to analyze.

Why this exists
---------------
The pipeline writes normalized outputs to disk. Analysis commands typically want
"the latest run per tool" without manually threading run_id strings around.

This module supports two filesystem layouts:

v2 (suite/case layout preferred):
  <runs_dir>/<tool>/<run_id>/normalized.json

v1 (legacy layout):
  <runs_dir>/<tool>/<repo_name>/<run_id>/<repo_name>.normalized.json

Design goals
------------
- Keep discovery logic isolated from analysis logic.
- Keep it filesystem-only (no network, no scanner imports).
- Prefer cheap directory-name ordering (YYYYMMDDNN).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence


_RUN_ID_RE = re.compile(r"^\d{10}$")  # YYYYMMDDNN


@dataclass(frozen=True)
class DiscoveredRun:
    """A discovered normalized output for a tool+repo."""

    tool: str
    repo_name: str
    run_id: str
    normalized_json: Path

    # Helpful metadata (best-effort; can be None)
    scan_date: Optional[str] = None
    commit: Optional[str] = None


def _is_run_id_dir(p: Path) -> bool:
    return p.is_dir() and bool(_RUN_ID_RE.match(p.name))


def _iter_run_dirs(base: Path) -> Iterable[Path]:
    if not base.exists() or not base.is_dir():
        return
    for p in base.iterdir():
        if _is_run_id_dir(p):
            yield p


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def _extract_metadata(normalized_json: Path) -> tuple[Optional[str], Optional[str]]:
    """Extract (scan_date, commit) from a normalized JSON file (best-effort)."""
    try:
        data = _load_json(normalized_json)
    except Exception:
        return None, None

    scan_date: Optional[str] = None
    commit: Optional[str] = None

    scan = data.get("scan")
    if isinstance(scan, dict) and isinstance(scan.get("scan_date"), str):
        scan_date = scan.get("scan_date")

    target_repo = data.get("target_repo")
    if isinstance(target_repo, dict) and isinstance(target_repo.get("commit"), str):
        commit = target_repo.get("commit")

    return scan_date, commit


def parse_scan_date(scan_date: str | None) -> Optional[datetime]:
    """Parse ISO-ish scan_date strings into a datetime (best-effort)."""
    if not scan_date or not isinstance(scan_date, str):
        return None
    s = scan_date.strip()
    if not s:
        return None

    # Examples observed: 2025-12-28T15:32:04.046660
    #                   2025-12-01T11:11:50+01:00
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def find_latest_normalized_json(
    *,
    runs_dir: Path,
    tool: str,
    repo_name: str,
) -> DiscoveredRun:
    """Return the latest normalized JSON for ``tool`` and ``repo_name``.

    Latest is determined by the highest run_id directory name (YYYYMMDDNN).

    Raises
    ------
    FileNotFoundError if no suitable normalized JSON exists.
    """

    # v1 legacy base (runs/<tool>/<repo_name>/...)
    base_v1 = runs_dir / tool / repo_name
    # v2 preferred base (runs/<tool>/<run_id>/...)
    base_v2 = runs_dir / tool

    run_dirs_v1 = sorted(_iter_run_dirs(base_v1), key=lambda p: p.name)
    run_dirs_v2 = sorted(_iter_run_dirs(base_v2), key=lambda p: p.name)

    # Prefer v1 if it actually exists/has runs; otherwise try v2.
    if run_dirs_v1:
        base = base_v1
        run_dirs = run_dirs_v1
        candidates = [f"{repo_name}.normalized.json", "normalized.json"]
    elif run_dirs_v2:
        base = base_v2
        run_dirs = run_dirs_v2
        candidates = ["normalized.json", f"{repo_name}.normalized.json"]
    else:
        raise FileNotFoundError(
            "No run directories found under either layout:\n"
            f"  v2: {base_v2}\n"
            f"  v1: {base_v1}"
        )

    # Iterate from newest to oldest until we find the normalized JSON.
    for rd in reversed(run_dirs):
        for fname in candidates:
            candidate = rd / fname
            if candidate.exists() and candidate.is_file():
                scan_date, commit = _extract_metadata(candidate)
                return DiscoveredRun(
                    tool=tool,
                    repo_name=repo_name,
                    run_id=rd.name,
                    normalized_json=candidate,
                    scan_date=scan_date,
                    commit=commit,
                )

    raise FileNotFoundError(
        f"Found run dirs under {base} but none contained a normalized JSON file "
        f"(tried: {', '.join(candidates)})"
    )


def discover_latest_runs(
    *,
    runs_dir: Path,
    repo_name: str,
    tools: Sequence[str],
    allow_missing: bool = False,
) -> Dict[str, DiscoveredRun]:
    """Discover the latest run per tool for a repo.

    Returns a dict keyed by tool.

    Notes
    -----
    - By default, tools that are missing raise ``FileNotFoundError``.
      This is usually what you want for CI.
    - If ``allow_missing=True``, missing tools are skipped.
    """

    out: Dict[str, DiscoveredRun] = {}
    for tool in tools:
        try:
            out[tool] = find_latest_normalized_json(runs_dir=runs_dir, tool=tool, repo_name=repo_name)
        except FileNotFoundError:
            if allow_missing:
                continue
            raise
    return out
