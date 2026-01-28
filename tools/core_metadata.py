"""tools/core_metadata.py

Standard run metadata creation.

All scanner adapters write a ``metadata.json``. This module contains the shared
logic so each tool writes consistent provenance fields.
"""

from __future__ import annotations

import hashlib
import json
import platform
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .core_git import get_commit_author_info, get_git_branch, get_pipeline_git_commit
from .core_repo import TargetRepo


_EPHEMERAL_CONFIG_KEYS = {
    # Common run-specific fields (do not affect scanner *configuration*)
    "status",
    "error",
    "log_path",
    "raw_results_path",
    "repo_local_path",
    "scan_time_seconds",
    "issues_count",
    "alerts_count",
    "warnings_count",
    "exit_code",
}


def _config_hash(scanner: str, scanner_version: str, extra: Optional[Dict[str, Any]]) -> str:
    """Hash stable, config-like fields for provenance.

    This intentionally excludes run-specific paths and timings.
    """
    cfg_extra = {k: v for k, v in (extra or {}).items() if k not in _EPHEMERAL_CONFIG_KEYS}
    payload = {
        "scanner": scanner,
        "scanner_version": scanner_version,
        "config": cfg_extra,
    }
    raw = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def get_commit_author_info_compat(
    repo_path, commit: Optional[str]
) -> Dict[str, Optional[str]]:
    """Backwards-compatible helper.

    Returns keys with None if commit info isn't available; never raises.
    """
    base = {
        "commit_author_name": None,
        "commit_author_email": None,
        "commit_date": None,
    }
    if not commit:
        return base
    try:
        base.update(get_commit_author_info(repo_path, commit))
    except Exception:
        # Swallow errors: metadata should not break scans.
        pass
    return base


def build_run_metadata(
    *,
    scanner: str,
    scanner_version: str,
    repo: TargetRepo,
    run_id: str,
    command_str: str,
    scan_time_seconds: float,
    exit_code: int,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Standard metadata dict written by all scanners."""
    author_info = get_commit_author_info_compat(repo.repo_path, repo.commit)
    cfg_hash = _config_hash(scanner, scanner_version, extra)

    data: Dict[str, Any] = {
        "scanner": scanner,
        "scanner_version": scanner_version,
        "repo_name": repo.repo_name,
        "repo_url": repo.repo_url,
        "repo_path": str(repo.repo_path),
        "repo_branch": get_git_branch(repo.repo_path),
        "repo_commit": repo.commit,
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "command": command_str,
        "scan_time_seconds": scan_time_seconds,
        "exit_code": exit_code,
        "config_hash": cfg_hash,
        "pipeline_git_commit": get_pipeline_git_commit(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        **author_info,
    }
    if extra:
        data.update(extra)
    return data
