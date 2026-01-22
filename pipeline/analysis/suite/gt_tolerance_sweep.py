"""pipeline.analysis.gt_tolerance_sweep

Deterministic GT tolerance sweep + (optional) auto-selection.

Why this exists
---------------
GT matching between tool findings/clusters and ground-truth markers can be
sensitive to small line offsets (e.g., 1-6 lines). Hardcoding a single
"magic" gt_tolerance is brittle across suites and can hide GT authoring
issues.

This module provides:
- a deterministic sweep across candidate tolerances
- a compact comparison report (CSV)
- per-tolerance snapshots of suite-level analysis artifacts
- an optional auto-selection strategy (smallest tolerance that reaches
  >= X% of the maximum observed GT-positive clusters)

Design constraints
------------------
- Non-interactive (CI-safe): never prompts.
- Deterministic: stable candidate ordering, stable output ordering.
- Reuses existing analysis pipeline: orchestrates repeated AnalyzeRequest
  runs and then reuses suite_triage_* builders.

Outputs
-------
Written under runs/suites/<suite_id>/analysis/:

- _tables/gt_tolerance_sweep_report.csv
- _tables/gt_tolerance_sweep_tool_stats.csv
- gt_tolerance_sweep.json

Snapshots for each tolerance are written under:
  analysis/_sweeps/gt_tol_<t>/

Notes
-----
This module is intentionally small and filesystem-first. It should not import
heavy dependencies.
"""

from __future__ import annotations

import csv
import json
import math
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from pipeline.analysis.io.write_artifacts import write_csv, write_json
from pipeline.analysis.suite_triage_calibration import tool_weights_from_calibration
from pipeline.orchestrator import AnalyzeRequest
from pipeline.pipeline import SASTBenchmarkPipeline
from pipeline.suites.bundles import safe_name


DEFAULT_GT_TOLERANCE_CANDIDATES: List[int] = [0, 1, 2, 3, 5, 10]


def parse_gt_tolerance_candidates(raw: Any) -> List[int]:
    """Parse comma-separated gt_tolerance candidate list.

    Parameters
    ----------
    raw:
        CLI arg value (usually a comma-separated string). If None/empty,
        returns DEFAULT_GT_TOLERANCE_CANDIDATES.

    Returns
    -------
    List[int]
        De-duplicated, non-negative ints in stable order.
    """

    if raw is None:
        return list(DEFAULT_GT_TOLERANCE_CANDIDATES)

    s = str(raw).strip()
    if not s:
        return list(DEFAULT_GT_TOLERANCE_CANDIDATES)

    # Split on commas and whitespace.
    parts: List[str] = []
    for chunk in s.replace(";", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        # Support accidental space-separated lists like "0 1 2".
        if " " in chunk or "\t" in chunk or "\n" in chunk:
            for sub in chunk.split():
                if sub.strip():
                    parts.append(sub.strip())
        else:
            parts.append(chunk)

    out: List[int] = []
    seen: set[int] = set()
    for p in parts:
        try:
            v = int(str(p).strip())
        except Exception:
            continue
        if v < 0:
            continue
        if v in seen:
            continue
        seen.add(v)
        out.append(v)

    return out or list(DEFAULT_GT_TOLERANCE_CANDIDATES)


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


def _read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with Path(path).open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [dict(r) for r in reader if isinstance(r, dict)]


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return int(default)
        if isinstance(x, bool):
            return int(x)
        return int(float(str(x)))
    except Exception:
        return int(default)


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        if x is None:
            return float(default)
        return float(str(x))
    except Exception:
        return float(default)


def _parse_json_list(raw: str) -> List[str]:
    s = str(raw or "").strip()
    if not s:
        return []
    try:
        v = json.loads(s)
        if isinstance(v, list):
            return [str(x) for x in v if str(x).strip()]
    except Exception:
        return []
    return []


@dataclass(frozen=True)
class DatasetOverlapStats:
    clusters_total: int
    gt_overlap_1: int
    gt_overlap_0: int
    gt_overlap_rate: float

    gt_ids_covered: int
    clusters_multi_gt: int
    gt_ids_multi_cluster: int
    max_clusters_per_gt_id: int
    max_gt_ids_per_cluster: int


def ambiguity_warnings_from_overlap_stats(stats: DatasetOverlapStats) -> List[str]:
    """Derive deterministic ambiguity warnings from overlap stats.

    These warnings are meant to surface *many-to-one* and *one-to-many*
    relationships between GT IDs and clusters that become more common at
    higher tolerances.

    The caller is responsible for recording counts separately. This function
    only produces short, stable warning strings suitable for CSV/JSON outputs.
    """

    warnings: List[str] = []

    # Many-to-one: one cluster overlaps multiple GT IDs.
    if int(stats.clusters_multi_gt) > 0:
        warnings.append(f"many_to_one_clusters={int(stats.clusters_multi_gt)}")

    # One-to-many: one GT ID overlaps multiple clusters.
    if int(stats.gt_ids_multi_cluster) > 0:
        warnings.append(f"one_to_many_gt_ids={int(stats.gt_ids_multi_cluster)}")

    # Shape indicators (helpful to understand severity).
    if int(stats.max_gt_ids_per_cluster) > 1:
        warnings.append(f"max_gt_ids_per_cluster={int(stats.max_gt_ids_per_cluster)}")
    if int(stats.max_clusters_per_gt_id) > 1:
        warnings.append(f"max_clusters_per_gt_id={int(stats.max_clusters_per_gt_id)}")

    return warnings


def _compute_dataset_overlap_stats(dataset_csv: Path) -> DatasetOverlapStats:
    rows = _read_csv_rows(dataset_csv)

    total = len(rows)
    pos = 0
    neg = 0

    gt_id_to_cluster_count: Dict[str, int] = {}

    clusters_multi_gt = 0
    max_gt_ids_per_cluster = 0

    for r in rows:
        ov = _safe_int(r.get("gt_overlap"), 0)
        if ov == 1:
            pos += 1
        else:
            neg += 1

        ids: List[str] = []
        raw_ids_json = str(r.get("gt_overlap_ids_json") or "").strip()
        if raw_ids_json:
            ids = _parse_json_list(raw_ids_json)

        # Fallback: semicolon list
        if not ids:
            raw_ids = str(r.get("gt_overlap_ids") or "").strip()
            if raw_ids:
                ids = [p.strip() for p in raw_ids.split(";") if p.strip()]

        if ids:
            uniq = sorted(set(ids))
            max_gt_ids_per_cluster = max(max_gt_ids_per_cluster, len(uniq))
            if len(uniq) > 1:
                clusters_multi_gt += 1
            for gid in uniq:
                gt_id_to_cluster_count[gid] = int(gt_id_to_cluster_count.get(gid, 0)) + 1

    gt_ids_covered = len(gt_id_to_cluster_count)
    gt_ids_multi_cluster = sum(1 for _gid, c in gt_id_to_cluster_count.items() if int(c) > 1)
    max_clusters_per_gt_id = max([int(c) for c in gt_id_to_cluster_count.values()], default=0)

    rate = (float(pos) / float(total)) if total else 0.0

    return DatasetOverlapStats(
        clusters_total=int(total),
        gt_overlap_1=int(pos),
        gt_overlap_0=int(neg),
        gt_overlap_rate=float(f"{rate:.6f}"),
        gt_ids_covered=int(gt_ids_covered),
        clusters_multi_gt=int(clusters_multi_gt),
        gt_ids_multi_cluster=int(gt_ids_multi_cluster),
        max_clusters_per_gt_id=int(max_clusters_per_gt_id),
        max_gt_ids_per_cluster=int(max_gt_ids_per_cluster),
    )


def _extract_macro_metrics(
    triage_eval_summary: Mapping[str, Any],
    *,
    strategies: Sequence[str] = ("baseline", "agreement", "calibrated"),
    ks: Sequence[int] = (1, 3, 5, 10, 25),
) -> Dict[str, float]:
    """Flatten macro precision/coverage into a single dict of columns."""

    out: Dict[str, float] = {}

    macro = triage_eval_summary.get("macro") if isinstance(triage_eval_summary, dict) else None
    if not isinstance(macro, dict):
        return out

    for strat in strategies:
        s_obj = macro.get(strat)
        if not isinstance(s_obj, dict):
            continue
        for k in ks:
            k_obj = s_obj.get(str(k))
            if not isinstance(k_obj, dict):
                continue
            p = k_obj.get("precision")
            c = k_obj.get("gt_coverage")
            if p is not None:
                out[f"macro_precision_{strat}_k{k}"] = float(_safe_float(p, default=0.0))
            if c is not None:
                out[f"macro_gt_coverage_{strat}_k{k}"] = float(_safe_float(c, default=0.0))

    # Calibrated vs baseline deltas (only where both exist).
    for k in ks:
        p_cal = out.get(f"macro_precision_calibrated_k{k}")
        p_base = out.get(f"macro_precision_baseline_k{k}")
        c_cal = out.get(f"macro_gt_coverage_calibrated_k{k}")
        c_base = out.get(f"macro_gt_coverage_baseline_k{k}")

        if p_cal is not None and p_base is not None:
            out[f"delta_macro_precision_calibrated_vs_baseline_k{k}"] = float(f"{(p_cal - p_base):.6f}")
        if c_cal is not None and c_base is not None:
            out[f"delta_macro_gt_coverage_calibrated_vs_baseline_k{k}"] = float(f"{(c_cal - c_base):.6f}")

    return out


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


def run_gt_tolerance_sweep(
    *,
    pipeline: SASTBenchmarkPipeline,
    suite_root: Path,
    suite_id: str,
    suite_dir: Path,
    cases: Sequence[Any],
    tools: Sequence[str],
    tolerance: int,
    gt_source: str,
    analysis_filter: str,
    exclude_prefixes: Sequence[str],
    include_harness: bool,
    candidates: Sequence[int],
    out_dirname: str = "analysis",
) -> Dict[str, Any]:
    """Run a deterministic sweep of gt_tolerance values.

    This function *mutates* the suite-level analysis outputs while it runs.
    Always rely on the snapshots/report for comparisons.

    Returns
    -------
    Dict[str, Any]
        JSON-serializable payload including flattened rows and output paths.
    """

    from pipeline.analysis.suite_triage_dataset import build_triage_dataset
    from pipeline.analysis.suite_triage_calibration import build_triage_calibration
    from pipeline.analysis.suite_triage_eval import build_triage_eval

    suite_dir = Path(suite_dir).resolve()
    analysis_dir = suite_dir / out_dirname
    tables_dir = analysis_dir / "_tables"
    sweeps_dir = analysis_dir / "_sweeps"

    tables_dir.mkdir(parents=True, exist_ok=True)
    sweeps_dir.mkdir(parents=True, exist_ok=True)

    # Normalize candidates deterministically.
    cand_list = [int(x) for x in candidates if int(x) >= 0]
    if not cand_list:
        cand_list = list(DEFAULT_GT_TOLERANCE_CANDIDATES)

    # stable order
    cand_list = sorted(set(cand_list))

    rows_out: List[Dict[str, Any]] = []
    tool_rows_out: List[Dict[str, Any]] = []
    snapshots: List[Dict[str, Any]] = []

    for t in cand_list:
        print("\n" + "=" * 72)
        print(f"🔍 GT tolerance sweep: gt_tolerance={t}")

        # Ensure per-case analysis doesn't pick up an old calibration.
        disable_suite_calibration(suite_dir, out_dirname=out_dirname)

        # Re-analyze all cases with the candidate tolerance.
        rc_overall = 0
        for idx, case in enumerate(cases, start=1):
            case_id = str(getattr(case, "case_id", "") or "").strip() or "unknown"
            print("\n" + "-" * 72)
            print(f"🔁 Analyze sweep {idx}/{len(cases)}: {case_id} (gt_tolerance={t})")

            case_dir = (suite_dir / "cases" / safe_name(case_id)).resolve()

            try:
                areq = AnalyzeRequest(
                    metric="suite",
                    case=case,
                    suite_root=Path(suite_root),
                    suite_id=str(suite_id),
                    case_path=str(case_dir),
                    tools=tuple(tools),
                    tolerance=int(tolerance),
                    gt_tolerance=int(t),
                    gt_source=str(gt_source),
                    analysis_filter=str(analysis_filter),
                    exclude_prefixes=tuple(exclude_prefixes or ()),
                    include_harness=bool(include_harness),
                    skip_suite_aggregate=True,
                )
                rc = int(pipeline.analyze(areq))
            except Exception as e:
                print(f"  ❌ analyze failed for {case_id} @ gt_tolerance={t}: {e}")
                rc = 2

            rc_overall = max(rc_overall, rc)

        # Build suite-level artifacts for THIS tolerance.
        ds = build_triage_dataset(suite_dir=suite_dir, suite_id=str(suite_id))
        cal = build_triage_calibration(suite_dir=suite_dir, suite_id=str(suite_id))
        ev = build_triage_eval(suite_dir=suite_dir, suite_id=str(suite_id), include_tool_marginal=False)

        dataset_csv = Path(str(ds.get("out_csv") or (analysis_dir / "_tables" / "triage_dataset.csv"))).resolve()

        stats = _compute_dataset_overlap_stats(dataset_csv)

        # Ambiguity warnings (many-to-one / one-to-many). Keep both counts and
        # human-readable warnings in the sweep outputs so CI/users can spot
        # tolerance-induced matching ambiguity.
        amb_warnings = ambiguity_warnings_from_overlap_stats(stats)

        # Tool stats (for a separate tool-stats table)
        cal_json_path = analysis_dir / "triage_calibration.json"
        cal_obj: Dict[str, Any] = {}
        if cal_json_path.exists():
            try:
                cal_obj = json.loads(cal_json_path.read_text(encoding="utf-8"))
            except Exception:
                cal_obj = {}

        weights = tool_weights_from_calibration(cal_obj)

        report_csv_path = analysis_dir / "_tables" / "triage_calibration_report.csv"
        if report_csv_path.exists():
            try:
                for r in _read_csv_rows(report_csv_path):
                    tool = str(r.get("tool") or "").strip()
                    if not tool:
                        continue
                    tool_rows_out.append(
                        {
                            "gt_tolerance": int(t),
                            "tool": tool,
                            "tp": _safe_int(r.get("tp"), 0),
                            "fp": _safe_int(r.get("fp"), 0),
                            "p_smoothed": _safe_float(r.get("p_smoothed"), 0.0),
                            "weight": _safe_float(r.get("weight"), float(weights.get(tool, 0.0))),
                        }
                    )
            except Exception:
                # Best-effort
                pass
        else:
            # Fallback to JSON-only weights (no tp/fp details).
            for tool, w in sorted(weights.items()):
                tool_rows_out.append(
                    {
                        "gt_tolerance": int(t),
                        "tool": str(tool),
                        "tp": "",
                        "fp": "",
                        "p_smoothed": "",
                        "weight": float(w),
                    }
                )

        # Eval metrics (macro flatten)
        metrics = _extract_macro_metrics(ev)

        # Snapshot suite-level artifacts
        snap_dir = sweeps_dir / f"gt_tol_{int(t)}"
        _snapshot_suite_analysis(suite_dir=suite_dir, snapshot_dir=snap_dir, out_dirname=out_dirname)
        snapshots.append({"gt_tolerance": int(t), "snapshot_dir": str(snap_dir)})

        row: Dict[str, Any] = {
            "gt_tolerance": int(t),
            "analysis_rc": int(rc_overall),
            "clusters_total": int(stats.clusters_total),
            "gt_overlap_1": int(stats.gt_overlap_1),
            "gt_overlap_0": int(stats.gt_overlap_0),
            "gt_overlap_rate": float(stats.gt_overlap_rate),
            "gt_ids_covered": int(stats.gt_ids_covered),

            # Explicit ambiguity fields (aliases make the meaning obvious).
            # - many_to_one: a single cluster overlaps multiple GT IDs
            # - one_to_many: a single GT ID overlaps multiple clusters
            "many_to_one_clusters": int(stats.clusters_multi_gt),
            "one_to_many_gt_ids": int(stats.gt_ids_multi_cluster),

            "clusters_multi_gt": int(stats.clusters_multi_gt),
            "gt_ids_multi_cluster": int(stats.gt_ids_multi_cluster),
            "max_clusters_per_gt_id": int(stats.max_clusters_per_gt_id),
            "max_gt_ids_per_cluster": int(stats.max_gt_ids_per_cluster),

            # Warning summary (stable strings, safe to parse).
            "gt_ambiguity_warning": 1 if amb_warnings else 0,
            "gt_ambiguity_warning_count": int(len(amb_warnings)),
            "gt_ambiguity_warnings_json": json.dumps(amb_warnings, ensure_ascii=False),

            "snapshot_dir": str(snap_dir),
        }
        row.update(metrics)

        rows_out.append(row)

        print("\n📊 Sweep row")
        print(
            f"  gt_tolerance={t} clusters={stats.clusters_total} gt_overlap_1={stats.gt_overlap_1} "
            f"multi_gt_clusters={stats.clusters_multi_gt} gt_ids_multi_cluster={stats.gt_ids_multi_cluster}"
        )

    # Stable sort by gt_tolerance
    rows_out.sort(key=lambda r: int(r.get("gt_tolerance", 0)))
    tool_rows_out.sort(key=lambda r: (int(r.get("gt_tolerance", 0)), str(r.get("tool") or "")))

    out_report_csv = tables_dir / "gt_tolerance_sweep_report.csv"
    out_tool_csv = tables_dir / "gt_tolerance_sweep_tool_stats.csv"
    out_json = analysis_dir / "gt_tolerance_sweep.json"

    write_csv(out_report_csv, rows_out)
    write_csv(out_tool_csv, tool_rows_out, fieldnames=["gt_tolerance", "tool", "tp", "fp", "p_smoothed", "weight"])

    payload: Dict[str, Any] = {
        "schema_version": "gt_tolerance_sweep_v1",
        "suite_id": str(suite_id),
        "suite_dir": str(suite_dir),
        "candidates": list(cand_list),
        "out_report_csv": str(out_report_csv),
        "out_tool_csv": str(out_tool_csv),
        "snapshots": list(snapshots),
        "rows": list(rows_out),
    }

    write_json(out_json, payload, indent=2)

    print("\n✅ GT tolerance sweep report")
    print(f"  Report : {out_report_csv}")
    print(f"  Tools  : {out_tool_csv}")
    print(f"  JSON   : {out_json}")

    return payload


def select_gt_tolerance_auto(rows: Sequence[Mapping[str, Any]], *, min_fraction: float = 0.95) -> Dict[str, Any]:
    """Select a gt_tolerance deterministically from sweep rows.

    Strategy (v1)
    -------------
    - Let M = max(gt_overlap_1) across candidates.
    - Choose the smallest tolerance t such that gt_overlap_1(t) >= ceil(M * min_fraction).

    This is intentionally simple and explainable.

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
            "warnings": ["No sweep rows available; defaulting to gt_tolerance=0"],
        }

    max_pos = max(int(_safe_int(r.get("gt_overlap_1"), 0)) for r in rr)

    if max_pos <= 0:
        warnings.append("All sweep candidates produced 0 GT-positive clusters (gt_overlap_1=0). GT authoring/matching may be broken.")

    mf = float(min_fraction)
    if mf <= 0:
        mf = 0.0
    if mf > 1.0:
        mf = 1.0

    # ceil with a tiny epsilon to avoid float quirks
    required = int(math.ceil((float(max_pos) * mf) - 1e-9)) if max_pos > 0 else 0

    chosen_row: Optional[Dict[str, Any]] = None
    for r in rr:
        pos = int(_safe_int(r.get("gt_overlap_1"), 0))
        if pos >= required:
            chosen_row = dict(r)
            break

    if chosen_row is None:
        # Fallback: pick smallest tolerance
        chosen_row = dict(rr[0])
        warnings.append("Auto selection could not satisfy threshold; defaulting to smallest candidate")

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
