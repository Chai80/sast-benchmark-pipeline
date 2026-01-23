from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from pipeline.analysis.compute.pairwise import build_pairwise_agreement_rows
from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json

from ..common.locations import ensure_location_clusters
from ..common.store_keys import StoreKeys


@register_stage(
    "pairwise_agreement",
    kind="analysis",
    description="Compute pairwise Jaccard similarity across tools over clustered locations.",
    requires=(StoreKeys.LOCATION_CLUSTERS,),
    produces=(StoreKeys.PAIRWISE_ROWS,),
)
def stage_pairwise(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    clusters = ensure_location_clusters(ctx, store)

    rows = build_pairwise_agreement_rows(clusters, tools=list(ctx.tools))
    store.put(StoreKeys.PAIRWISE_ROWS, rows)

    out_csv = Path(ctx.out_dir) / "pairwise_agreement.csv"
    out_json = Path(ctx.out_dir) / "pairwise_agreement.json"

    if "csv" in ctx.formats:
        write_csv(out_csv, rows, fieldnames=["tool_a", "tool_b", "clusters_a", "clusters_b", "intersection", "union", "jaccard"])
        store.add_artifact("pairwise_agreement_csv", out_csv)
    if "json" in ctx.formats:
        write_json(out_json, rows)
        store.add_artifact("pairwise_agreement_json", out_json)

    return {"pairs": len(rows)}
