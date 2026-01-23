from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from pipeline.analysis.compute.triage_queue import (
    TRIAGE_QUEUE_FIELDNAMES,
    TRIAGE_QUEUE_SCHEMA_VERSION,
    build_triage_queue_rows,
    rank_triage_rows,
)
from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json

from ..common.locations import ensure_location_clusters
from ..common.store_keys import StoreKeys


@register_stage(
    "triage_queue",
    kind="analysis",
    description="Create a ranked triage queue of hotspots to review first.",
    requires=(StoreKeys.LOCATION_CLUSTERS,),
    produces=(StoreKeys.TRIAGE_ROWS,),
)
def stage_triage(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    clusters = ensure_location_clusters(ctx, store)

    rows, meta = build_triage_queue_rows(ctx, clusters)
    store.put(StoreKeys.TRIAGE_ROWS, rows)

    out_csv = Path(ctx.out_dir) / "triage_queue.csv"
    out_json = Path(ctx.out_dir) / "triage_queue.json"
    if "csv" in ctx.formats:
        write_csv(
            out_csv,
            rows,
            fieldnames=TRIAGE_QUEUE_FIELDNAMES,
        )
        store.add_artifact("triage_queue_csv", out_csv)
    if "json" in ctx.formats:
        write_json(out_json, rows)
        store.add_artifact("triage_queue_json", out_json)

    return meta
