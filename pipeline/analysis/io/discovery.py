from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

_RUN_ID_RE = re.compile(r"^\d{10}$")  # YYYYMMDDNN


def _discover_repo_dir(tool_dir: Path, repo_name: Optional[str]) -> Optional[Path]:
    """Discover the per-repo directory under a tool directory (legacy layout).

    Legacy layout:
      <runs_dir>/<tool>/<repo_name>/<run_id>/...

    In suite layout, the repo layer is usually flattened away and tool_dir
    contains run_id folders directly.
    """
    if not tool_dir.exists() or not tool_dir.is_dir():
        return None

    if repo_name:
        p = tool_dir / repo_name
        if p.exists() and p.is_dir():
            return p

    # Fallback: if only one directory exists, assume it's the repo dir.
    dirs = [d for d in tool_dir.iterdir() if d.is_dir()]
    if len(dirs) == 1:
        return dirs[0]

    # Case-insensitive match
    if repo_name:
        for d in dirs:
            if d.name.lower() == repo_name.lower():
                return d

    return None


def find_latest_run_dir(*, runs_dir: Path, tool: str, repo_name: str) -> Path:
    """Find the latest run directory for tool+repo.

    Supports both layouts:

    v2 (suite/case preferred):
      <runs_dir>/<tool>/<run_id>/...

    v1 (legacy):
      <runs_dir>/<tool>/<repo_name>/<run_id>/...
    """
    runs_dir = Path(runs_dir)
    tool_dir = runs_dir / tool
    if not tool_dir.exists():
        raise FileNotFoundError(f"Tool directory not found: {tool_dir}")

    # v2: tool_dir has run_id folders directly
    run_dirs = [d for d in tool_dir.iterdir() if d.is_dir() and _RUN_ID_RE.match(d.name)]
    if run_dirs:
        return max(run_dirs, key=lambda p: p.name)

    # v1: tool_dir/<repo_name>/<run_id>
    repo_dir = _discover_repo_dir(tool_dir, repo_name)
    if repo_dir:
        run_dirs = [d for d in repo_dir.iterdir() if d.is_dir() and _RUN_ID_RE.match(d.name)]
        if run_dirs:
            return max(run_dirs, key=lambda p: p.name)

    raise FileNotFoundError(
        f"No run_id folders found for tool={tool!r} repo={repo_name!r} under {tool_dir}"
    )


def find_latest_normalized_json(*, runs_dir: Path, tool: str, repo_name: str) -> Path:
    """Find the latest normalized JSON for tool+repo."""
    run_dir = find_latest_run_dir(runs_dir=runs_dir, tool=tool, repo_name=repo_name)

    candidates = [
        run_dir / "normalized.json",
        run_dir / f"{repo_name}.normalized.json",
        run_dir / f"{repo_name}.normalized.json".replace("-", "_"),  # legacy safety
    ]
    for p in candidates:
        if p.exists() and p.is_file():
            return p

    # Last-resort: any *.normalized.json in the run dir
    norm_files = sorted(run_dir.glob("*.normalized.json"))
    if norm_files:
        return norm_files[0]

    raise FileNotFoundError(f"Normalized JSON not found in: {run_dir}")
