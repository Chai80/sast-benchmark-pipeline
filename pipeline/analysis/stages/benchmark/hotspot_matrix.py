from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from pipeline.analysis.compute.hotspot_matrix import build_hotspot_matrix_rows
from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json

from ..common.locations import ensure_location_clusters
from ..common.store_keys import StoreKeys


@register_stage(
    "hotspot_matrix",
    kind="analysis",
    description="Rank clustered locations (hotspots) by cross-tool agreement.",
    requires=(StoreKeys.LOCATION_CLUSTERS,),
    produces=(StoreKeys.HOTSPOT_MATRIX_ROWS,),
)
def stage_hotspot_matrix(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    clusters = ensure_location_clusters(ctx, store)

    rows = build_hotspot_matrix_rows(clusters, tools=list(ctx.tools))
    store.put(StoreKeys.HOTSPOT_MATRIX_ROWS, rows)

    out_json = Path(ctx.out_dir) / "hotspot_matrix.json"
    out_csv = Path(ctx.out_dir) / "hotspot_matrix.csv"
    if "json" in ctx.formats:
        write_json(out_json, rows)
        store.add_artifact("hotspot_matrix_json", out_json)
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
        store.add_artifact("hotspot_matrix_csv", out_csv)

    return {"hotspots": len(rows)}
