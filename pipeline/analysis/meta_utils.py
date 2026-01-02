"""pipeline.analysis.meta_utils

Shared metadata helpers for analysis artifacts.

Goal
----
Keep every filesystem artifact self-describing and consistent, without forcing a DB.

This module provides:
- a standard meta envelope (schema_version, created_at, stage, pipeline_git_sha)
- best-effort git SHA capture for traceability
- tiny helpers to merge stage-specific meta with the standard fields

Design constraints
------------------
- stdlib only
- never fail the pipeline if git is unavailable
"""

from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

# /repo/pipeline/analysis/meta_utils.py -> parents[2] == /repo
REPO_ROOT_DIR = Path(__file__).resolve().parents[2]

# Increment if you make breaking changes to artifact schemas.
SCHEMA_VERSION = 1


def utc_now_iso() -> str:
    """UTC timestamp in ISO 8601 with 'Z' suffix and no microseconds."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _looks_like_git_sha(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{7,40}", s.strip()))


def get_pipeline_git_sha(repo_root: Path = REPO_ROOT_DIR) -> Optional[str]:
    """Best-effort git commit SHA for traceability.

    Priority:
      1) PIPELINE_GIT_SHA env var (CI-friendly)
      2) git rev-parse HEAD (if git + .git are available)
    """
    env_sha = (os.getenv("PIPELINE_GIT_SHA") or "").strip()
    if env_sha and _looks_like_git_sha(env_sha):
        return env_sha

    try:
        sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root),
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        return sha if _looks_like_git_sha(sha) else None
    except Exception:
        return None


def with_standard_meta(
    meta: Optional[Mapping[str, Any]],
    *,
    stage: str,
    repo: Optional[str] = None,
    tool_names: Optional[Sequence[str]] = None,
    **extra: Any,
) -> Dict[str, Any]:
    """Merge stage-specific meta with standard meta fields.

    - Never mutates the input mapping
    - Always sets created_at + stage + schema_version
    - Adds pipeline_git_sha if available
    - If repo/tool_names are provided, sets them explicitly for consistency
    """
    out: Dict[str, Any] = {}
    if isinstance(meta, Mapping):
        # shallow copy
        out.update(dict(meta))

    # Standard fields (always present)
    out["schema_version"] = SCHEMA_VERSION
    out["created_at"] = utc_now_iso()
    out["stage"] = stage

    sha = get_pipeline_git_sha()
    if sha:
        out["pipeline_git_sha"] = sha

    if repo is not None:
        out["repo"] = repo
    if tool_names is not None:
        out["tool_names"] = list(tool_names)

    # Stage extras (only if not None)
    for k, v in extra.items():
        if v is not None:
            out[k] = v

    return out
