from __future__ import annotations

"""Pairwise agreement computations."""

from itertools import combinations
from typing import Any, Dict, List, Sequence


def build_pairwise_agreement_rows(
    clusters: Sequence[Dict[str, Any]], *, tools: Sequence[str]
) -> List[Dict[str, Any]]:
    """Compute pairwise Jaccard similarity across tools over clustered locations."""

    tools_l = list(tools)

    tool_to_clusters: Dict[str, set[str]] = {t: set() for t in tools_l}
    for c in clusters:
        cid = str(c.get("cluster_id") or "")
        for t in c.get("tools") or []:
            if t in tool_to_clusters:
                tool_to_clusters[t].add(cid)

    rows: List[Dict[str, Any]] = []
    for a, b in combinations(tools_l, 2):
        sa = tool_to_clusters.get(a) or set()
        sb = tool_to_clusters.get(b) or set()
        inter = len(sa & sb)
        union = len(sa | sb)
        j = (inter / union) if union else 0.0
        rows.append(
            {
                "tool_a": a,
                "tool_b": b,
                "clusters_a": len(sa),
                "clusters_b": len(sb),
                "intersection": inter,
                "union": union,
                "jaccard": round(j, 6),
            }
        )

    return rows
