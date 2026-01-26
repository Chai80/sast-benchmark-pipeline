from __future__ import annotations

"""cli.common

Small shared helpers for CLI command modules.

The CLI is intentionally split by "mode" (scan/benchmark/suite/analyze). Some
small helpers are useful across multiple modes; keeping them here avoids subtle
drift when two files copy/paste the same logic.
"""

from pathlib import Path
from typing import Optional


def derive_runs_repo_name(
    *, repo_url: Optional[str], repo_path: Optional[str], fallback: str
) -> str:
    """Best-effort repo name used by scanners under runs/<tool>/<repo_name>/..."""
    if repo_url:
        last = repo_url.rstrip("/").split("/")[-1]
        return last[:-4] if last.endswith(".git") else last
    if repo_path:
        return Path(repo_path).resolve().name
    return fallback


def parse_csv(raw: Optional[str]) -> list[str]:
    """Parse a comma-separated list value into a list of non-empty strings."""
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]
