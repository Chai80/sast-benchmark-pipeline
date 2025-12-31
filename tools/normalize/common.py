"""tools/normalize/common.py

Shared helpers for building *schema blocks* for the normalized JSON output.

This module is intentionally focused on *normalization/schema construction*
and should not contain filesystem IO. Keep IO helpers (read/write JSON,
read_line_content, etc.) in :mod:`tools.io` so there is a single canonical
implementation used by all scanners.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Optional


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


