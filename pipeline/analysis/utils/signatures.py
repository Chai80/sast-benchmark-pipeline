from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional

from .path_norm import normalize_file_path


def location_key(finding: Dict[str, Any], *, repo_name: Optional[str] = None) -> str:
    """Best-effort stable key for a single finding location."""
    fp = normalize_file_path(str(finding.get("file_path") or ""), repo_name=repo_name)
    line = finding.get("line_number")
    end = finding.get("end_line_number")
    try:
        line_i = int(line) if line is not None else 0
    except Exception:
        line_i = 0
    try:
        end_i = int(end) if end is not None else line_i
    except Exception:
        end_i = line_i
    return f"{fp}:{line_i}-{end_i}"


def cluster_locations(
    items: Iterable[Dict[str, Any]],
    *,
    tolerance: int = 3,
    repo_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Cluster findings into location buckets within each file.

    This is a best-effort line-range clustering used to compare tools that may
    report slightly different line numbers for the same underlying issue.

    Parameters
    ----------
    items:
        Iterable of dicts. Expected keys: tool, file_path, line_number, end_line_number.
    tolerance:
        Two findings are merged into the same cluster if their start line is within
        `tolerance` lines of the current cluster end.
    """
    tol = max(0, int(tolerance))
    by_file: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for it in items or []:
        if not isinstance(it, dict):
            continue
        fp_raw = str(it.get("file_path") or "")
        fp = normalize_file_path(fp_raw, repo_name=repo_name)
        it2 = dict(it)
        it2["file_path_norm"] = fp
        by_file[fp].append(it2)

    clusters: List[Dict[str, Any]] = []

    for fp, group in by_file.items():
        unknown = []
        numbered = []
        for it in group:
            ln = it.get("line_number")
            try:
                ln_i = int(ln) if ln is not None else None
            except Exception:
                ln_i = None
            if ln_i is None or ln_i <= 0:
                unknown.append(it)
            else:
                it["_line"] = ln_i
                try:
                    en = it.get("end_line_number")
                    it["_end_line"] = int(en) if en is not None else ln_i
                except Exception:
                    it["_end_line"] = ln_i
                numbered.append(it)

        if unknown:
            tools = sorted(
                {
                    str(it.get("tool") or "")
                    for it in unknown
                    if it.get("tool") is not None
                }
            )
            clusters.append(
                {
                    "cluster_id": f"{fp}:unknown",
                    "file_path": fp,
                    "start_line": None,
                    "end_line": None,
                    "tools": tools,
                    "tool_count": len(tools),
                    "items": unknown,
                }
            )

        numbered.sort(key=lambda x: int(x.get("_line", 0)))

        current: Optional[Dict[str, Any]] = None
        for it in numbered:
            ln = int(it.get("_line", 0))
            en = int(it.get("_end_line", ln))
            if current is None:
                current = {
                    "file_path": fp,
                    "start_line": ln,
                    "end_line": en,
                    "items": [it],
                }
                continue

            # Merge if this finding is within tolerance of current cluster end.
            if ln <= int(current["end_line"]) + tol:
                current["items"].append(it)
                current["end_line"] = max(int(current["end_line"]), en)
            else:
                # finalize current
                tools = sorted(
                    {
                        str(x.get("tool") or "")
                        for x in current["items"]
                        if x.get("tool") is not None
                    }
                )
                cid = f"{fp}:{current['start_line']}-{current['end_line']}"
                clusters.append(
                    {
                        "cluster_id": cid,
                        "file_path": fp,
                        "start_line": int(current["start_line"]),
                        "end_line": int(current["end_line"]),
                        "tools": tools,
                        "tool_count": len(tools),
                        "items": list(current["items"]),
                    }
                )
                current = {
                    "file_path": fp,
                    "start_line": ln,
                    "end_line": en,
                    "items": [it],
                }

        if current is not None:
            tools = sorted(
                {
                    str(x.get("tool") or "")
                    for x in current["items"]
                    if x.get("tool") is not None
                }
            )
            cid = f"{fp}:{current['start_line']}-{current['end_line']}"
            clusters.append(
                {
                    "cluster_id": cid,
                    "file_path": fp,
                    "start_line": int(current["start_line"]),
                    "end_line": int(current["end_line"]),
                    "tools": tools,
                    "tool_count": len(tools),
                    "items": list(current["items"]),
                }
            )

    # Stable sort: most-agreed first, then by file/line.
    clusters.sort(
        key=lambda c: (
            -int(c.get("tool_count", 0)),
            str(c.get("file_path")),
            int(c.get("start_line") or 0),
        )
    )
    return clusters
