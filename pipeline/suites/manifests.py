"""pipeline.suites.manifests

Central writers for suite/case *state files*.

Why this exists
---------------
The suite output folder contains a few "state" artifacts that other parts of the
pipeline depend on:

- ``suite.json``   (suite index)
- ``summary.csv``  (one row per case)
- ``case.json``    (per-case manifest)
- ``runs/suites/LATEST`` (pointer for "most recent" suite)

Historically these were written/updated from several places (execution code,
layout code, and legacy helpers). That makes it easy for the file formats to
drift over time.

This module provides one obvious place to:
- define the JSON schema shape for ``case.json``
- define how suite indexes (``suite.json`` / ``summary.csv``) are updated
- keep suite-level writes best-effort (never break scans)

Design notes
------------
This file is intentionally *not* an "architecture layer". It's a small set of
pure-ish helpers for writing manifests.

It delegates to the existing legacy implementation in ``pipeline.suites.bundles``
for suite index update behavior (to keep semantics identical), but exposes a
suite-named API for new call sites.
"""

from __future__ import annotations

import platform
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Sequence

from pipeline.core import ROOT_DIR as REPO_ROOT
from pipeline.suites.bundles import BundlePaths
from pipeline.suites import bundles as _bundles
from pipeline.suites.layout import SuitePaths
from tools.io import write_json


# ---------------------------------------------------------------------------
# Provenance helpers
# ---------------------------------------------------------------------------


def _pipeline_git_commit() -> Optional[str]:
    """Best-effort commit hash for *this* pipeline repo (not the scanned repo)."""
    try:
        out = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return out or None
    except Exception:
        return None


def runtime_environment() -> Dict[str, Any]:
    """Runtime provenance captured into manifests (safe, no secrets)."""
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "pipeline_git_commit": _pipeline_git_commit(),
    }


# ---------------------------------------------------------------------------
# Internal conversion helpers
# ---------------------------------------------------------------------------


def _to_bundle_paths(paths: SuitePaths) -> BundlePaths:
    """Convert :class:`SuitePaths` to legacy :class:`BundlePaths`.

    The legacy bundle implementation contains the stable suite.json / summary.csv
    update logic. We keep it as an implementation detail to avoid churn.
    """

    return BundlePaths(
        bundle_root=paths.suite_root,
        target=paths.case_id,
        bundle_id=paths.suite_id,
        suite_dir=paths.suite_dir,
        cases_dir=paths.cases_dir,
        suite_readme_path=paths.suite_readme_path,
        suite_json_path=paths.suite_json_path,
        suite_summary_path=paths.suite_summary_path,
        latest_pointer_path=paths.latest_pointer_path,
        case_dir=paths.case_dir,
        tool_runs_dir=paths.tool_runs_dir,
        analysis_dir=paths.analysis_dir,
        gt_dir=paths.gt_dir,
        case_json_path=paths.case_json_path,
    )


# ---------------------------------------------------------------------------
# Suite-level writers
# ---------------------------------------------------------------------------


def update_latest_pointer(paths: SuitePaths) -> None:
    """Write/overwrite runs/suites/LATEST with the current suite id."""
    _bundles.write_latest_pointer(_to_bundle_paths(paths))


def write_suite_manifest(paths: SuitePaths, case_manifest: Dict[str, Any]) -> None:
    """Update suite.json for a completed case (best-effort)."""

    bp = _to_bundle_paths(paths)

    def warn(msg: str) -> None:
        # Persist suite-level warnings without breaking scans.
        _bundles._append_suite_warning(bp, msg)  # type: ignore[attr-defined]

    try:
        _bundles._ensure_suite_readme(bp)  # type: ignore[attr-defined]
        _bundles._ensure_suite_json(bp)  # type: ignore[attr-defined]
        _bundles._update_suite_json(bp, case_manifest, warn=warn)  # type: ignore[attr-defined]
    except Exception as e:
        warn(f"write_suite_manifest_failed: {e}")


def append_summary_row(paths: SuitePaths) -> None:
    """Update summary.csv after a case completes (best-effort).

    NOTE: The current implementation regenerates the full summary from case
    manifests under ``cases/``. This keeps behavior identical to the legacy
    implementation and avoids subtle drift.
    """

    bp = _to_bundle_paths(paths)

    def warn(msg: str) -> None:
        _bundles._append_suite_warning(bp, msg)  # type: ignore[attr-defined]

    try:
        _bundles._write_suite_summary(bp, warn=warn)  # type: ignore[attr-defined]
    except Exception as e:
        warn(f"append_summary_row_failed: {e}")


def update_suite_artifacts(paths: SuitePaths, case_manifest: Dict[str, Any]) -> None:
    """Convenience: update suite.json + summary.csv for one case."""
    write_suite_manifest(paths, case_manifest)
    append_summary_row(paths)


# ---------------------------------------------------------------------------
# Case-level writer
# ---------------------------------------------------------------------------


def write_case_manifest(
    *,
    paths: SuitePaths,
    invocation_mode: str,
    argv: Optional[Sequence[str]],
    python_executable: Optional[str],
    skip_analysis: bool,
    repo_label: str,
    repo_url: Optional[str],
    repo_path: Optional[str],
    runs_repo_name: Optional[str],
    expected_branch: Optional[str],
    expected_commit: Optional[str],
    track: Optional[str],
    tags: Dict[str, Any],
    git_branch: Optional[str],
    git_commit: Optional[str],
    started: str,
    finished: Optional[str],
    scanners_requested: Sequence[str],
    scanners_used: Sequence[str],
    tool_runs: Dict[str, Any],
    analysis: Optional[Dict[str, Any]],
    warnings: Sequence[str],
    errors: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Build + write ``case.json``.

    This centralizes the on-disk schema for case manifests.
    """

    manifest: Dict[str, Any] = {
        "suite": {"id": paths.suite_id, "suite_dir": str(paths.suite_dir)},
        "case": {
            "id": paths.case_id,
            "case_dir": str(paths.case_dir),
            "expected_branch": expected_branch,
            "expected_commit": expected_commit,
            "track": str(track) if track else None,
            "tags": dict(tags or {}),
        },
        "repo": {
            "label": repo_label,
            "repo_url": repo_url,
            "repo_path": repo_path,
            "runs_repo_name": runs_repo_name,
            "git_branch": git_branch,
            "git_commit": git_commit,
        },
        "invocation": {
            "mode": invocation_mode,
            "argv": list(argv) if argv else None,
            "python": python_executable,
            "skip_analysis": bool(skip_analysis),
            "environment": runtime_environment(),
        },
        "timestamps": {"started": started, "finished": finished},
        "scanners_requested": list(scanners_requested),
        "scanners_used": list(scanners_used),
        "tool_runs": tool_runs,
        "analysis": analysis,
        "warnings": list(warnings),
        "errors": list(errors or []),
    }

    # Best-effort write: never fail a scan due to manifest IO.
    try:
        write_json(paths.case_json_path, manifest)
    except Exception as e:
        # Preserve a visible on-disk warning even if the case manifest write failed.
        try:
            ts = datetime.now(timezone.utc).isoformat()
            p = paths.case_dir / "case_warnings.log"
            with p.open("a", encoding="utf-8") as f:
                f.write(f"[{ts}] write_case_manifest_failed: {e}\n")
        except Exception:
            pass

    return manifest
