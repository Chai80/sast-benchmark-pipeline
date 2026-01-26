from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from pipeline.analysis.compute.triage_features import (
    TRIAGE_FEATURES_FIELDNAMES,
    build_triage_features_rows,
)
from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv

from ..common.locations import ensure_location_clusters
from ..common.store_keys import StoreKeys


@register_stage(
    "triage_features",
    kind="analysis",
    description="Emit DS-ready cluster-level feature table (analysis/_tables/triage_features.csv).",
    requires=(StoreKeys.LOCATION_CLUSTERS,),
)
def stage_triage_features(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    clusters = ensure_location_clusters(ctx, store)
    triage_rows = store.get(StoreKeys.TRIAGE_ROWS) or []

    rows = build_triage_features_rows(ctx, clusters, triage_rows=triage_rows)

    out_csv = Path(ctx.out_dir) / "_tables" / "triage_features.csv"
    write_csv(
        out_csv,
        rows,
        fieldnames=TRIAGE_FEATURES_FIELDNAMES,
    )
    store.add_artifact("triage_features_csv", out_csv)

    return {"rows": len(rows)}
