from __future__ import annotations

"""pipeline.analysis.stages.gt.matching

Matching logic between GT items and tool finding locations.
"""

from collections import Counter, defaultdict
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .normalize import coerce_int


def tool_locations(location_items: Sequence[Mapping[str, Any]]) -> Dict[str, List[Tuple[str, int]]]:
    """Build a map of tool -> [(file_path, line_number), ...]."""
    by_tool: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
    for it in location_items or []:
        tool = str(it.get("tool") or "").strip()
        fp = str(it.get("file_path") or "").strip()
        ln = coerce_int(it.get("line_number"), default=0)
        if tool and fp:
            by_tool[tool].append((fp, ln))
    return by_tool


def match_tools_for_gt(
    *,
    gt_file: str,
    gt_start: int,
    gt_end: int,
    tool_locs: Mapping[str, Sequence[Tuple[str, int]]],
    tol: int,
) -> List[str]:
    """Return list of tools that have at least one finding within tolerance."""
    matched: List[str] = []
    lo = int(gt_start) - int(tol)
    hi = int(gt_end) + int(tol)
    for tool, locs in tool_locs.items():
        for fp, ln in locs:
            if fp != gt_file:
                continue
            if lo <= int(ln) <= hi:
                matched.append(tool)
                break
    return sorted(set(matched))


def score_gt_items(
    *,
    gt_items: Sequence[Mapping[str, Any]],
    tool_locs: Mapping[str, Sequence[Tuple[str, int]]],
    gt_tolerance: int,
) -> Tuple[
    List[Dict[str, Any]],
    int,
    Counter[str],
    Counter[str],
    Counter[str],
    Counter[str],
    Counter[str],
]:
    """Score GT items against tool locations.

    Returns:
      (rows, matched_gt_items, per_tool_matched, by_set_total, by_set_matched,
       by_track_total, by_track_matched)
    """
    rows: List[Dict[str, Any]] = []
    per_tool_matched: Counter[str] = Counter()
    by_set_total: Counter[str] = Counter()
    by_set_matched: Counter[str] = Counter()
    by_track_total: Counter[str] = Counter()
    by_track_matched: Counter[str] = Counter()

    matched_gt_items = 0

    for gt in gt_items or []:
        gt_id = str(gt.get("id") or "")
        gt_file = str(gt.get("file") or "")
        gt_start = coerce_int(gt.get("start_line"), default=0)
        gt_end = coerce_int(gt.get("end_line"), default=gt_start)
        gt_track = str(gt.get("track") or "unknown")
        gt_set = str(gt.get("set") or "unknown")

        by_set_total[gt_set] += 1
        by_track_total[gt_track] += 1

        matched_tools = match_tools_for_gt(
            gt_file=gt_file,
            gt_start=gt_start,
            gt_end=gt_end,
            tool_locs=tool_locs,
            tol=gt_tolerance,
        )
        matched = bool(matched_tools)
        if matched:
            matched_gt_items += 1
            by_set_matched[gt_set] += 1
            by_track_matched[gt_track] += 1
            for t in matched_tools:
                per_tool_matched[str(t)] += 1

        rows.append(
            {
                "gt_id": gt_id,
                "track": gt_track,
                "set": gt_set,
                "file": gt_file,
                "start_line": gt_start,
                "end_line": gt_end,
                "matched": bool(matched),
                "matched_tool_count": len(matched_tools),
                "matched_tools": ",".join(matched_tools),
            }
        )

    return rows, matched_gt_items, per_tool_matched, by_set_total, by_set_matched, by_track_total, by_track_matched
