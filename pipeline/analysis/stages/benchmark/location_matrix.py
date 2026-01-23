from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json
from pipeline.analysis.utils.signatures import cluster_locations


from ..common.locations import build_location_items
from ..common.severity import max_severity
from ..common.store_keys import StoreKeys


@register_stage(
    "location_matrix",
    kind="analysis",
    description="Cluster findings into location buckets and write a per-location tool matrix.",
    requires=(StoreKeys.FINDINGS_BY_TOOL,),
    produces=(StoreKeys.LOCATION_ITEMS, StoreKeys.LOCATION_CLUSTERS, StoreKeys.LOCATION_MATRIX_ROWS),
)
def stage_location_matrix(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    items = build_location_items(ctx, store)
    clusters = cluster_locations(items, tolerance=ctx.tolerance, repo_name=ctx.repo_name)
    store.put(StoreKeys.LOCATION_CLUSTERS, clusters)

    tools = list(ctx.tools)

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
                **{f"{t}_count": int(tool_counts.get(t, 0)) for t in tools},
            }
        )

    store.put(StoreKeys.LOCATION_MATRIX_ROWS, rows)

    out_json = Path(ctx.out_dir) / "location_matrix.json"
    out_csv = Path(ctx.out_dir) / "location_matrix.csv"

    if "json" in ctx.formats:
        write_json(out_json, rows)
        store.add_artifact("location_matrix_json", out_json)
    if "csv" in ctx.formats:
        fieldnames = [
            "cluster_id",
            "file_path",
            "start_line",
            "end_line",
            "tool_count",
            "tools",
            "total_findings",
            "max_severity",
        ] + [f"{t}_count" for t in tools]
        write_csv(out_csv, rows, fieldnames=fieldnames)
        store.add_artifact("location_matrix_csv", out_csv)

    return {"clusters": len(rows)}

