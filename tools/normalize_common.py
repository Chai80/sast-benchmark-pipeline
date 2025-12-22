"""tools/normalize_common.py

Shared helpers for building and writing the normalized JSON schema.

Why this exists
--------------
Every scanner script needs to:
  - build the same header blocks (target_repo, scan_info)
  - attach per-finding metadata (schema v1.1)
  - optionally read a source line for context
  - write JSON in a consistent way

Centralizing these utilities keeps each tool-specific normalizer small and
prevents copy/paste drift.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Optional


def write_json(path: Path, data: Any) -> None:
    """Write JSON with stable pretty-printing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def build_target_repo(metadata: Mapping[str, Any]) -> dict:
    """Build the schema 'target_repo' block from metadata.json."""
    return {
        "name": metadata.get("repo_name"),
        "url": metadata.get("repo_url"),
        "commit": metadata.get("repo_commit"),
        "commit_author_name": metadata.get("commit_author_name"),
        "commit_author_email": metadata.get("commit_author_email"),
        "commit_date": metadata.get("commit_date"),
    }


def build_scan_info(metadata: Mapping[str, Any], raw_results_path: Path) -> dict:
    """Build the schema 'scan' block from metadata.json."""
    return {
        "run_id": metadata.get("run_id"),
        "scan_date": metadata.get("timestamp"),
        "command": metadata.get("command"),
        "raw_results_path": str(raw_results_path),
        "scan_time_seconds": metadata.get("scan_time_seconds"),
        "exit_code": metadata.get("exit_code"),
        "metadata_path": "metadata.json",
    }


def build_per_finding_metadata(
    *,
    tool: str,
    tool_version: Optional[str],
    target_repo: dict,
    scan_info: dict,
) -> dict:
    """Build the per-finding 'metadata' block (schema v1.1)."""
    return {
        "tool": tool,
        "tool_version": tool_version,
        "target_repo": target_repo,
        "scan": scan_info,
    }


def read_line_content(
    repo_path: Path,
    file_path: Optional[str],
    line_number: Optional[int],
) -> Optional[str]:
    """Best-effort read of the source line at (file_path, line_number)."""
    if not file_path or not line_number:
        return None

    try:
        file_abs = repo_path / file_path
        lines = file_abs.read_text(encoding="utf-8", errors="replace").splitlines()
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1].rstrip("\n")
    except OSError:
        return None

    return None
