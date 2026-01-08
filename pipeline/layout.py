"""pipeline.layout

Filesystem layout helpers.

This module is a thin wrapper around :mod:`pipeline.bundles` (the suite/case
layout implementation) plus a small set of helper functions used by the CLI and
analysis code.

Why this exists
---------------
Historically, directory naming, run discovery, and "where did this tool write
its output" logic lived in the CLI. That grows quickly into spaghetti.

Phase 1 of the CLI refactor moves:
- suite/case path computation
- "latest run" discovery inside a tool output folder

...into one place.

Notes
-----
- We keep the underlying implementation in pipeline.bundles for backwards
  compatibility (some older patches and docs still refer to "bundles").
- New code should prefer the "suite" terminology exposed here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

from sast_benchmark.io.layout import (
    discover_latest_run_dir as _discover_latest_run_dir,
    discover_repo_dir as _discover_repo_dir,
)

from pipeline.bundles import (
    BundlePaths as SuitePaths,
    ensure_bundle_dirs as ensure_suite_dirs,
    get_bundle_paths,
    new_bundle_id,
    resolve_bundle_dir,
    update_suite_artifacts,
    write_latest_pointer as write_latest_suite_pointer,
)


def new_suite_id() -> str:
    """Generate a new suite id (sortable UTC timestamp)."""
    return new_bundle_id()


def get_suite_paths(
    *,
    case_id: str,
    suite_id: str,
    suite_root: Union[str, Path] = "runs/suites",
) -> SuitePaths:
    """Compute filesystem paths for one case inside one suite."""
    return get_bundle_paths(target=case_id, bundle_id=suite_id, bundle_root=suite_root)


def resolve_case_dir(
    *,
    case_id: str,
    suite_id: str,
    suite_root: Union[str, Path] = "runs/suites",
) -> Path:
    """Resolve the case directory for an existing suite.

    suite_id may be 'latest' (uses runs/suites/LATEST fallback logic).
    """
    return resolve_bundle_dir(target=case_id, bundle_id=suite_id, bundle_root=suite_root)


def discover_repo_dir(output_root: Path, prefer: Optional[str] = None) -> Optional[Path]:
    """Backwards-compatible wrapper for :func:`sast_benchmark.io.layout.discover_repo_dir`."""
    return _discover_repo_dir(output_root, prefer)


def discover_latest_run_dir(repo_dir: Path) -> Optional[Path]:
    """Backwards-compatible wrapper for :func:`sast_benchmark.io.layout.discover_latest_run_dir`."""
    return _discover_latest_run_dir(repo_dir)
