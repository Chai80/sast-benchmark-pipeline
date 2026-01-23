from __future__ import annotations

"""Location matrix computations.

This module turns clustered locations into a per-location "tool matrix" table.
"""

from collections import Counter
from typing import Any, Dict, List, Sequence

from pipeline.analysis.stages.common.severity import max_severity


def build_location_matrix_rows(clusters: Sequence[Dict[str, Any]], *, tools: Sequence[str]) -> List[Dict[str, Any]]:
    """Build rows for `location_matrix.csv`/`location_matrix.json`.

    Parameters
    ----------
    clusters:
        Output of `cluster_locations()`.
    tools:
        Tool names included in the run; determines which per-tool *_count columns exist.
    """

    tools_l = list(tools)

    rows: List[Dict[str, Any]] = []
    for c in clusters:
        tool_counts = Counter()
        for it in c.get("items") or []:
            tool_counts[str(it.get("tool") or "")] += 1

        sev, _rank = max_severity(list(c.get("items") or []))
        rows.append(
            {
                "cluster_id": c.get("cluster_id"),
                "file_path": c.get("file_path"),
                "start_line": c.get("start_line"),
                "end_line": c.get("end_line"),
                "tool_count": c.get("tool_count"),
                "tools": ",".join(c.get("tools") or []),
                "total_findings": sum(tool_counts.values()),
                "max_severity": sev,
                **{f"{t}_count": int(tool_counts.get(t, 0)) for t in tools_l},
            }
        )

    return rows
