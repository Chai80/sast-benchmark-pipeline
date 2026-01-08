"""sast_benchmark.io

Filesystem contracts and IO helpers.

Design principle
----------------
The benchmark output layout is a public contract.

If multiple tools implement their own "where do files go" logic, the repo
inevitably accumulates duplicated heuristics (suite mode detection, v1/v2
layouts, candidate filenames...). This module centralizes those rules so they
can evolve in one place.
"""

from __future__ import annotations

from .layout import (
    RUN_ID_RE,
    RunPaths,
    discover_repo_dir,
    discover_latest_run_dir,
    find_latest_normalized_json,
    find_latest_run_dir,
    is_suite_mode,
    prepare_run_paths,
)

__all__ = [
    "RUN_ID_RE",
    "RunPaths",
    "discover_repo_dir",
    "discover_latest_run_dir",
    "find_latest_normalized_json",
    "find_latest_run_dir",
    "is_suite_mode",
    "prepare_run_paths",
]
