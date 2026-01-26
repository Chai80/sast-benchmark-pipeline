from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from pipeline.analysis.compute.location_matrix import build_location_matrix_rows
from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json
from pipeline.analysis.utils.signatures import cluster_locations

from ..common.locations import build_location_items
from ..common.store_keys import StoreKeys


@register_stage(
    "location_matrix",
    kind="analysis",
    description="Cluster findings into location buckets and write a per-location tool matrix.",
    requires=(StoreKeys.FINDINGS_BY_TOOL,),
    produces=(
        StoreKeys.LOCATION_ITEMS,
        StoreKeys.LOCATION_CLUSTERS,
        StoreKeys.LOCATION_MATRIX_ROWS,
    ),
)
def stage_location_matrix(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    items = build_location_items(ctx, store)
    clusters = cluster_locations(
        items, tolerance=ctx.tolerance, repo_name=ctx.repo_name
    )
    store.put(StoreKeys.LOCATION_CLUSTERS, clusters)

    rows = build_location_matrix_rows(clusters, tools=list(ctx.tools))
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
        ] + [f"{t}_count" for t in ctx.tools]
        write_csv(out_csv, rows, fieldnames=fieldnames)
        store.add_artifact("location_matrix_csv", out_csv)

    return {"clusters": len(rows)}
