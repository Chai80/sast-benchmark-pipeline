"""pipeline.analysis.suite.gt_tolerance.snapshot

Snapshot / hygiene helpers for GT tolerance sweeps.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

def disable_suite_calibration(suite_dir: Path, *, out_dirname: str = "analysis") -> Optional[Path]:
    """Temporarily disable suite-level triage calibration.

    Per-case analysis (triage_queue stage) will automatically pick up
    runs/suites/<suite_id>/analysis/triage_calibration.json when it exists.

    For a sweep, we want *baseline* triage_rank to be stable and not influenced
    by a calibration file from a previous tolerance.

    This function moves triage_calibration.json to
    analysis/_checkpoints/triage_calibration.disabled.json if it exists.

    Returns
    -------
    Optional[Path]
        The new disabled path when a file was moved, otherwise None.
    """

    suite_dir = Path(suite_dir).resolve()
    cal_path = suite_dir / out_dirname / "triage_calibration.json"
    if not cal_path.exists():
        return None

    # Keep sweep hygiene: do not leave confusing artifacts in analysis/.
    # We stash the previous calibration under analysis/_checkpoints/.
    checkpoints_dir = cal_path.parent / "_checkpoints"
    disabled = checkpoints_dir / "triage_calibration.disabled.json"
    try:
        disabled.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    try:
        if disabled.exists():
            disabled.unlink()
    except Exception:
        # Best-effort
        pass

    try:
        cal_path.rename(disabled)
        return disabled
    except Exception:
        # Best-effort: fall back to copy+unlink.
        try:
            shutil.copy2(cal_path, disabled)
            cal_path.unlink()
            return disabled
        except Exception:
            return None



def _copy_if_exists(src: Path, dst: Path) -> None:
    try:
        if not src.exists() or not src.is_file():
            return
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    except Exception:
        return


def _snapshot_suite_analysis(
    *,
    suite_dir: Path,
    snapshot_dir: Path,
    out_dirname: str = "analysis",
) -> None:
    """Copy key suite-level analysis artifacts into a snapshot directory."""

    suite_dir = Path(suite_dir).resolve()
    analysis_dir = suite_dir / out_dirname
    snapshot_dir = Path(snapshot_dir).resolve()
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    # Top-level analysis artifacts
    for name in (
        "triage_calibration.json",
        "triage_calibration.log",
        "triage_dataset_build.json",
        "triage_dataset_build.log",
        "triage_eval.log",
    ):
        _copy_if_exists(analysis_dir / name, snapshot_dir / name)

    # Tables
    src_tables = analysis_dir / "_tables"
    dst_tables = snapshot_dir / "_tables"
    for name in (
        "triage_dataset.csv",
        "triage_calibration_report.csv",
        "triage_eval_summary.json",
        "triage_eval_by_case.csv",
        "triage_tool_utility.csv",
        "triage_eval_topk.csv",
        "README_triage_eval.md",
    ):
        _copy_if_exists(src_tables / name, dst_tables / name)


