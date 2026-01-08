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

import re
from pathlib import Path
from typing import Optional, Union

from pipeline.bundles import (
    BundlePaths as SuitePaths,
    ensure_bundle_dirs as ensure_suite_dirs,
    get_bundle_paths,
    new_bundle_id,
    resolve_bundle_dir,
    update_suite_artifacts,
    write_latest_pointer as write_latest_suite_pointer,
)


# Run ids are directories created by tools/core.create_run_dir().
#
# Current:  YYYYMMDDNNHHMMSS (16 digits)
# Legacy:   YYYYMMDDNN       (10 digits)
_RUN_ID_RE = re.compile(r"^\d{10}(\d{6})?$")


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
    """Discover the per-tool *run root* directory inside a case.

    Supports two layouts (historical compatibility):

    v2 (preferred):
      <output_root>/<run_id>/...

    v1 (legacy):
      <output_root>/<repo_name>/<run_id>/...

    Parameters
    ----------
    output_root:
        The tool output directory for a given case, e.g.:
          <case_dir>/tool_runs/semgrep
    prefer:
        If the legacy layout contains multiple repo folders, prefer this name.

    Returns
    -------
    Path | None
        The directory under which run_id folders exist.
    """
    if not output_root.exists() or not output_root.is_dir():
        return None

    # v2: output_root contains run_id directories directly.
    run_dirs = [d for d in output_root.iterdir() if d.is_dir() and _RUN_ID_RE.match(d.name)]
    if run_dirs:
        return output_root

    # v1: output_root contains repo folder(s); prefer an exact match if provided.
    if prefer:
        p = output_root / prefer
        if p.exists() and p.is_dir():
            return p

    dirs = [d for d in output_root.iterdir() if d.is_dir()]
    if len(dirs) == 1:
        return dirs[0]

    # If multiple, try to find a case-insensitive match
    if prefer:
        for d in dirs:
            if d.name.lower() == prefer.lower():
                return d

    return None


def discover_latest_run_dir(repo_dir: Path) -> Optional[Path]:
    """Return the latest run directory (YYYYMMDDNN) under repo_dir."""
    if not repo_dir.exists() or not repo_dir.is_dir():
        return None
    run_dirs = [d for d in repo_dir.iterdir() if d.is_dir() and _RUN_ID_RE.match(d.name)]
    if not run_dirs:
        return None
    return max(run_dirs, key=lambda p: p.name)
