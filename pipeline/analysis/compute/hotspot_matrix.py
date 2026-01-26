from __future__ import annotations

"""Hotspot matrix computations.

This stage ranks clustered locations ("hotspots") by cross-tool agreement.
"""

from collections import Counter
from typing import Any, Dict, List, Sequence

from pipeline.analysis.stages.common.severity import max_severity


def build_hotspot_matrix_rows(
    clusters: Sequence[Dict[str, Any]], *, tools: Sequence[str]
) -> List[Dict[str, Any]]:
    """Build ranked rows for `hotspot_matrix.csv`/`hotspot_matrix.json`."""

    tools_l = list(tools)

    rows: List[Dict[str, Any]] = []
    for c in clusters:
        tool_counts = Counter()
        for it in c.get("items") or []:
            tool_counts[str(it.get("tool") or "")] += 1

        sev, sev_rank = max_severity(list(c.get("items") or []))
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
                "_sev_rank": sev_rank,
                **{f"{t}_count": int(tool_counts.get(t, 0)) for t in tools_l},
            }
        )

    # Rank: most tools agree, then severity, then most findings.
    rows.sort(
        key=lambda r: (
            -int(r.get("tool_count", 0)),
            -int(r.get("_sev_rank", 0)),
            -int(r.get("total_findings", 0)),
            str(r.get("file_path") or ""),
            int(r.get("start_line") or 0),
        )
    )
    for r in rows:
        r.pop("_sev_rank", None)

    return rows
