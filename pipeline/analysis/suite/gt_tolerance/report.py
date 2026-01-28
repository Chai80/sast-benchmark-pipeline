"""pipeline.analysis.suite.gt_tolerance.report

Selection + persistence helpers for GT tolerance sweeps.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from pipeline.analysis.io.write_artifacts import write_json

from .metrics import _safe_int

def select_gt_tolerance_auto(
    rows: Sequence[Mapping[str, Any]], *, min_fraction: float = 0.95
) -> Dict[str, Any]:
    """Select a gt_tolerance deterministically from sweep rows.

    Strategy (v1)
    -------------
    - Let M = max(gt_overlap_1) across candidates.
    - Choose the smallest tolerance t such that gt_overlap_1(t) >= ceil(M * min_fraction).

    This is intentionally simple and explainable.

    Guardrails
    ----------
    - Prefer candidates where analysis_rc==0 when that information is present.

    Warnings
    --------
    - Emits warnings if all tolerances produce 0 GT-positive clusters.
    - Emits warnings if the selected tolerance produces potential ambiguity:
      * clusters_multi_gt > 0 (one cluster overlaps multiple GT IDs)
      * gt_ids_multi_cluster > 0 (one GT overlaps multiple clusters)
    """

    rr = [dict(r) for r in (rows or []) if isinstance(r, Mapping)]
    rr.sort(key=lambda r: int(_safe_int(r.get("gt_tolerance"), 0)))

    warnings: List[str] = []

    if not rr:
        return {
            "schema_version": "gt_tolerance_selection_v1",
            "selected_gt_tolerance": 0,
            "min_fraction": float(min_fraction),
            "max_gt_positive_clusters": 0,
            "required_min": 0,
            "analysis_rc_filter_applied": False,
            "warnings": ["No sweep rows available; defaulting to gt_tolerance=0"],
        }

    # Guardrail: if the sweep recorded per-candidate analysis_rc, prefer candidates
    # that succeeded (analysis_rc==0). If none succeeded, fall back to all rows.
    rr_used = rr
    rc_filter_applied = False

    any_failed = any(int(_safe_int(r.get("analysis_rc"), 0)) != 0 for r in rr)
    if any_failed:
        rr_ok = [r for r in rr if int(_safe_int(r.get("analysis_rc"), 0)) == 0]
        if rr_ok:
            rr_used = rr_ok
            rc_filter_applied = True
            warnings.append("Auto selection filtered to candidates with analysis_rc=0")
        else:
            warnings.append(
                "All sweep candidates had analysis_rc>0; selecting among all candidates anyway"
            )

    max_pos = max(int(_safe_int(r.get("gt_overlap_1"), 0)) for r in rr_used)

    if max_pos <= 0:
        warnings.append(
            "All sweep candidates produced 0 GT-positive clusters (gt_overlap_1=0). GT authoring/matching may be broken."
        )

    mf = float(min_fraction)
    if mf <= 0:
        mf = 0.0
    if mf > 1.0:
        mf = 1.0

    # ceil with a tiny epsilon to avoid float quirks
    required = int(math.ceil((float(max_pos) * mf) - 1e-9)) if max_pos > 0 else 0

    chosen_row: Optional[Dict[str, Any]] = None
    for r in rr_used:
        pos = int(_safe_int(r.get("gt_overlap_1"), 0))
        if pos >= required:
            chosen_row = dict(r)
            break

    if chosen_row is None:
        # Fallback: pick smallest tolerance
        chosen_row = dict(rr_used[0])
        warnings.append(
            "Auto selection could not satisfy threshold; defaulting to smallest candidate"
        )

    chosen = int(_safe_int(chosen_row.get("gt_tolerance"), 0))

    # Ambiguity warnings
    cmg = int(_safe_int(chosen_row.get("clusters_multi_gt"), 0))
    gmc = int(_safe_int(chosen_row.get("gt_ids_multi_cluster"), 0))
    if cmg > 0:
        warnings.append(
            f"Selected tolerance={chosen} has clusters overlapping multiple GT IDs (clusters_multi_gt={cmg}). "
            "This may indicate multiple GT items are close together; consider tightening tolerance or improving GT ranges."
        )
    if gmc > 0:
        warnings.append(
            f"Selected tolerance={chosen} has GT IDs overlapping multiple clusters (gt_ids_multi_cluster={gmc}). "
            "This can happen when a single GT marker sits near multiple tool clusters (or when tolerance is large)."
        )

    return {
        "schema_version": "gt_tolerance_selection_v1",
        "selected_gt_tolerance": int(chosen),
        "min_fraction": float(mf),
        "max_gt_positive_clusters": int(max_pos),
        "required_min": int(required),
        "analysis_rc_filter_applied": bool(rc_filter_applied),
        "selected_row": chosen_row,
        "warnings": warnings,
    }


def write_gt_tolerance_selection(
    *,
    suite_dir: Path,
    selection: Mapping[str, Any],
    sweep_payload: Optional[Mapping[str, Any]] = None,
    out_dirname: str = "analysis",
) -> Path:
    """Write the selected gt_tolerance + decision context to disk."""

    suite_dir = Path(suite_dir).resolve()
    analysis_dir = suite_dir / out_dirname
    out_path = analysis_dir / "gt_tolerance_selection.json"

    payload: Dict[str, Any] = {
        "schema_version": "gt_tolerance_selection_v1",
        "suite_id": str(suite_dir.name),
        "selected_gt_tolerance": int(_safe_int(selection.get("selected_gt_tolerance"), 0)),
        "selection": dict(selection),
    }

    if sweep_payload and isinstance(sweep_payload, Mapping):
        # Keep this reasonably small: include only paths + candidate rows.
        payload["sweep"] = {
            "schema_version": str(sweep_payload.get("schema_version") or ""),
            "candidates": list(sweep_payload.get("candidates") or []),
            "out_report_csv": str(sweep_payload.get("out_report_csv") or ""),
            "out_tool_csv": str(sweep_payload.get("out_tool_csv") or ""),
            "rows": list(sweep_payload.get("rows") or []),
        }

    write_json(out_path, payload, indent=2)
    return out_path
