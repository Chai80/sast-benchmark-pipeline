"""pipeline.suites.layout

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
from typing import Optional, Sequence, Union

from sast_benchmark.io.layout import (
    discover_latest_run_dir as _discover_latest_run_dir,
    discover_repo_dir as _discover_repo_dir,
)

from pipeline.suites.bundles import (
    BundlePaths as SuitePaths,
    anchor_under_repo_root,
    ensure_bundle_dirs as ensure_suite_dirs,
    get_bundle_paths,
    new_bundle_id,
    safe_name,
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

    Why this exists
    ---------------
    Different parts of the pipeline historically derived ``case_id`` differently
    (e.g., "juice_shop" vs "juice-shop"). The filesystem layout is the source of
    truth, so this resolver:

    1) resolves the suite id (supports ``latest``)
    2) lists directories under ``runs/suites/<suite_id>/cases/``
    3) attempts an exact match on the requested ``case_id``
    4) if not found, attempts a best-effort '-' <-> '_' normalization
    5) otherwise, errors with a helpful message listing valid case IDs

    This keeps scan output naming unchanged and only improves analysis-time
    discovery and error handling.
    """

    def _resolve_suite_id(*, root: Path, suite_id: str) -> str:
        bid = (suite_id or "").strip()
        if bid.lower() != "latest":
            return bid

        latest_file = root / "LATEST"
        if latest_file.exists():
            bid = latest_file.read_text(encoding="utf-8").strip()

        if bid:
            return bid

        if not root.exists():
            raise FileNotFoundError(f"No suites directory found: {root}")

        candidates = [p for p in root.iterdir() if p.is_dir()]
        if not candidates:
            raise FileNotFoundError(f"No suite runs found under: {root}")

        return max(candidates, key=lambda p: p.name).name

    def _canon_case_id(s: str) -> str:
        # Treat '-' and '_' as interchangeable for historical reasons.
        return s.replace("-", "_")

    root = anchor_under_repo_root(suite_root)
    resolved_suite_id = _resolve_suite_id(root=root, suite_id=str(suite_id))
    suite_dir = (root / safe_name(resolved_suite_id)).resolve()
    if not suite_dir.exists() or not suite_dir.is_dir():
        raise FileNotFoundError(f"Suite dir not found: {suite_dir}")

    cases_dir = suite_dir / "cases"
    if not cases_dir.exists() or not cases_dir.is_dir():
        raise FileNotFoundError(f"Cases dir not found: {cases_dir}")

    available: Sequence[str] = sorted([p.name for p in cases_dir.iterdir() if p.is_dir()])
    if not available:
        raise FileNotFoundError(f"No case directories found under: {cases_dir}")

    requested = safe_name(case_id)

    # 1) Exact match.
    if requested in available:
        return (cases_dir / requested).resolve()

    # 2) '-' <-> '_' normalization match.
    req_canon = _canon_case_id(requested)
    canon_matches = [c for c in available if _canon_case_id(c) == req_canon]
    if len(canon_matches) == 1:
        return (cases_dir / canon_matches[0]).resolve()

    # 3) Helpful error.
    hint: str
    if canon_matches:
        hint = (
            f"Ambiguous case id '{case_id}' for suite '{resolved_suite_id}'. "
            "Multiple case directories match after normalizing '-' and '_': "
            + ", ".join(sorted(canon_matches))
        )
    else:
        hint = f"Case id '{case_id}' not found in suite '{resolved_suite_id}'."

    valid = "\n".join(f"  - {c}" for c in available)
    raise FileNotFoundError(
        f"{hint}\n"
        f"Suite dir: {suite_dir}\n"
        f"Cases dir: {cases_dir}\n"
        f"Valid case IDs:\n{valid}"
    )


def discover_repo_dir(output_root: Path, prefer: Optional[str] = None) -> Optional[Path]:
    """Backwards-compatible wrapper for :func:`sast_benchmark.io.layout.discover_repo_dir`."""
    return _discover_repo_dir(output_root, prefer)


def discover_latest_run_dir(repo_dir: Path) -> Optional[Path]:
    """Backwards-compatible wrapper for :func:`sast_benchmark.io.layout.discover_latest_run_dir`."""
    return _discover_latest_run_dir(repo_dir)
