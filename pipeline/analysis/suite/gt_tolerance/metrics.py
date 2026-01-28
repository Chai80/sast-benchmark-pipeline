"""pipeline.analysis.suite.gt_tolerance.metrics

Small, deterministic helpers used by the GT tolerance sweep.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

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
            out[f"delta_macro_precision_calibrated_vs_baseline_k{k}"] = float(
                f"{(p_cal - p_base):.6f}"
            )
        if c_cal is not None and c_base is not None:
            out[f"delta_macro_gt_coverage_calibrated_vs_baseline_k{k}"] = float(
                f"{(c_cal - c_base):.6f}"
            )

    return out


