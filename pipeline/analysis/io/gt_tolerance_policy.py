"""pipeline.analysis.io.gt_tolerance_policy

Small helpers to resolve the *effective* GT matching tolerance for a suite.

Why this exists
---------------
GT matching tolerance (``gt_tolerance``) is a separate knob from the analysis
clustering tolerance.

In QA calibration flows we may deterministically select an effective
``gt_tolerance`` (via a sweep/auto policy) and persist that decision under the
suite directory:

- ``runs/suites/<suite_id>/analysis/gt_tolerance_selection.json``
- ``runs/suites/<suite_id>/suite.json`` (``plan.analysis.gt_tolerance_effective``)

To keep later analysis/calibration deterministic, execution paths can resolve
and prefer the recorded effective value rather than relying on the CLI default.

This module is intentionally lightweight (json + pathlib only) so it can be
imported from both execution and analysis code without creating import cycles.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def _safe_int(x: Any) -> Optional[int]:
    """Best-effort non-negative int parse."""

    try:
        if x is None:
            return None
        if isinstance(x, bool):
            return int(x)
        v = int(float(str(x).strip()))
        return v if v >= 0 else None
    except Exception:
        return None


def read_selected_gt_tolerance(*, suite_dir: Path) -> Optional[int]:
    """Read ``analysis/gt_tolerance_selection.json`` if present."""

    suite_dir = Path(suite_dir).resolve()
    sel_path = suite_dir / "analysis" / "gt_tolerance_selection.json"
    if not sel_path.exists() or not sel_path.is_file():
        return None

    try:
        raw = json.loads(sel_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    if not isinstance(raw, dict):
        return None

    # The canonical writer stores selected_gt_tolerance at the top-level.
    v = _safe_int(raw.get("selected_gt_tolerance"))
    return v


def read_suite_json_effective_gt_tolerance(*, suite_dir: Path) -> Optional[int]:
    """Read ``plan.analysis.gt_tolerance_effective`` from ``suite.json`` if present."""

    suite_dir = Path(suite_dir).resolve()
    suite_json = suite_dir / "suite.json"
    if not suite_json.exists() or not suite_json.is_file():
        return None

    try:
        raw = json.loads(suite_json.read_text(encoding="utf-8"))
    except Exception:
        return None

    if not isinstance(raw, dict):
        return None

    plan = raw.get("plan")
    if not isinstance(plan, dict):
        return None

    analysis = plan.get("analysis")
    if not isinstance(analysis, dict):
        return None

    return _safe_int(analysis.get("gt_tolerance_effective"))


def resolve_effective_gt_tolerance(
    *,
    suite_dir: Path,
    requested: int,
) -> Dict[str, Any]:
    """Resolve the effective GT matching tolerance for a suite.

    Priority (deterministic)
    ------------------------
    1) ``analysis/gt_tolerance_selection.json`` (``selected_gt_tolerance``)
    2) ``suite.json`` (``plan.analysis.gt_tolerance_effective``)
    3) ``requested`` (caller-provided)

    Returns
    -------
    Dict with:
      - requested_gt_tolerance: int
      - effective_gt_tolerance: int
      - source: str in {"selection_json", "suite_json", "requested"}
      - warnings: List[str]
    """

    suite_dir = Path(suite_dir).resolve()

    req = int(requested) if requested is not None else 0
    if req < 0:
        req = 0

    warnings: List[str] = []

    sel = read_selected_gt_tolerance(suite_dir=suite_dir)
    if sel is not None:
        eff = int(sel)
        if eff != req:
            warnings.append(
                f"gt_tolerance overridden by selection_json: requested={req} effective={eff}"
            )
        return {
            "requested_gt_tolerance": req,
            "effective_gt_tolerance": eff,
            "source": "selection_json",
            "warnings": warnings,
        }

    suite_eff = read_suite_json_effective_gt_tolerance(suite_dir=suite_dir)
    if suite_eff is not None:
        eff = int(suite_eff)
        if eff != req:
            warnings.append(
                f"gt_tolerance overridden by suite_json: requested={req} effective={eff}"
            )
        return {
            "requested_gt_tolerance": req,
            "effective_gt_tolerance": eff,
            "source": "suite_json",
            "warnings": warnings,
        }

    return {
        "requested_gt_tolerance": req,
        "effective_gt_tolerance": req,
        "source": "requested",
        "warnings": warnings,
    }
