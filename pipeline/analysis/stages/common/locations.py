from __future__ import annotations

"""pipeline.analysis.stages.common.locations

Helpers for turning findings into location items and clustered hotspots.
"""

from typing import Any, Dict, List

from pipeline.analysis.framework import AnalysisContext, ArtifactStore
from pipeline.analysis.utils.path_norm import normalize_file_path
from pipeline.analysis.utils.signatures import cluster_locations

from .findings import load_findings_by_tool
from .store_keys import StoreKeys


def build_location_items(
    ctx: AnalysisContext, store: ArtifactStore
) -> List[Dict[str, Any]]:
    """Flatten findings into a list of location items for clustering."""
    cached = store.get(StoreKeys.LOCATION_ITEMS)
    if isinstance(cached, list):
        return cached

    items: List[Dict[str, Any]] = []
    fb = load_findings_by_tool(ctx, store)

    for tool, findings in fb.items():
        for f in findings:
            if not isinstance(f, dict):
                continue
            fp = normalize_file_path(
                str(f.get("file_path") or ""), repo_name=ctx.repo_name
            )
            items.append(
                {
                    "tool": tool,
                    "finding_id": f.get("finding_id"),
                    "rule_id": f.get("rule_id"),
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "file_path": fp,
                    "line_number": f.get("line_number"),
                    "end_line_number": f.get("end_line_number"),
                    "vendor": f.get("vendor") or {},
                }
            )

    store.put(StoreKeys.LOCATION_ITEMS, items)
    return items


def ensure_location_clusters(
    ctx: AnalysisContext, store: ArtifactStore
) -> List[Dict[str, Any]]:
    """Return cached clusters if present; otherwise compute + cache them.

    This is a common precondition for many stages (hotspots, consensus, triage,
    pairwise agreement, drilldowns). Centralizing it avoids copy/pasting the same
    store wiring across many modules.
    """
    clusters = store.get(StoreKeys.LOCATION_CLUSTERS)
    if isinstance(clusters, list):
        return clusters

    items = build_location_items(ctx, store)
    clusters = cluster_locations(
        items, tolerance=ctx.tolerance, repo_name=ctx.repo_name
    )
    store.put(StoreKeys.LOCATION_CLUSTERS, clusters)
    return clusters
