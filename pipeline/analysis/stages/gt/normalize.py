from __future__ import annotations

"""pipeline.analysis.stages.gt.normalize

Normalization helpers for GT items.

The scorer accepts GT rows from multiple sources (markers, YAML). This module
converts those rows into a consistent internal shape that downstream matching
logic can rely on.
"""

from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from pipeline.analysis.utils.path_norm import normalize_file_path


def coerce_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def normalize_gt_item(raw: Mapping[str, Any], *, repo_name: str) -> Optional[Dict[str, Any]]:
    """Normalize a GT row into the internal shape.

    Returned dict always contains:
      - id
      - file
      - start_line
      - end_line
      - track
      - set
    """
    gt_id = str(raw.get("id") or raw.get("gt_id") or "").strip()

    file_raw = str(raw.get("file") or raw.get("file_path") or "").strip()
    fp = normalize_file_path(file_raw, repo_name=repo_name)
    if not fp:
        return None

    # lines
    start = raw.get("start_line")
    end = raw.get("end_line")
    if start is None:
        start = raw.get("line")
    if start is None:
        start = raw.get("line_number")
    start_i = coerce_int(start, default=0)

    if end is None:
        end = raw.get("end")
    if end is None:
        end_i = start_i
    else:
        end_i = coerce_int(end, default=start_i)

    if end_i < start_i:
        start_i, end_i = end_i, start_i

    # defaults
    track = str(raw.get("track") or "unknown").strip().lower() or "unknown"
    set_name = str(raw.get("set") or "unknown").strip() or "unknown"

    if not gt_id:
        gt_id = f"gt:{fp}:{start_i}:{end_i}"

    return {
        **dict(raw),
        "id": gt_id,
        "file": fp,
        "start_line": int(start_i),
        "end_line": int(end_i),
        "track": track,
        "set": set_name,
    }


def normalize_gt_items(raw_items: Sequence[Mapping[str, Any]], *, repo_name: str) -> List[Dict[str, Any]]:
    """Normalize a list of raw GT rows, dropping rows missing required fields."""
    gt_items: List[Dict[str, Any]] = []
    for row in raw_items or []:
        if not isinstance(row, Mapping):
            continue
        norm = normalize_gt_item(row, repo_name=repo_name)
        if norm:
            gt_items.append(norm)
    return gt_items


def filter_gt_items_by_track(
    gt_items: Sequence[Mapping[str, Any]],
    scoring_track: Optional[str],
) -> Tuple[List[Dict[str, Any]], int]:
    """Filter GT items by scoring track.

    Returns (filtered_items, filtered_out_count).
    """
    items: List[Dict[str, Any]] = [dict(x) for x in (gt_items or [])]
    if not scoring_track:
        return items, 0

    scoring_track_n = str(scoring_track).strip().lower()
    kept: List[Dict[str, Any]] = [
        it for it in items if str(it.get("track") or "unknown").lower() == scoring_track_n
    ]
    return kept, len(items) - len(kept)
