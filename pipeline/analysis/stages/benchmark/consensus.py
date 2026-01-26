from __future__ import annotations

"""pipeline.analysis.stages.consensus

Consensus (multi-tool agreement) scoring.

This stage is intentionally **GT-free**.

It answers a different question than GT scoring:

  - GT scoring: "Did a tool find the vulnerabilities we *know* exist?"
  - Consensus:  "Which hotspots do multiple tools agree on?"

Outputs
-------
Writes:
  - <analysis_dir>/consensus_queue.json
  - <analysis_dir>/consensus_queue.csv
"""

from pathlib import Path
from typing import Any, Dict

from pipeline.analysis.compute.consensus import build_consensus_rows_and_summary
from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json

from ..common.locations import ensure_location_clusters
from ..common.store_keys import StoreKeys


@register_stage(
    "consensus_queue",
    kind="analysis",
    description="Compute multi-tool agreement (consensus) per clustered location.",
    requires=(StoreKeys.LOCATION_CLUSTERS,),
    produces=(StoreKeys.CONSENSUS_ROWS, StoreKeys.CONSENSUS_SUMMARY),
)
def stage_consensus(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    clusters = ensure_location_clusters(ctx, store)

    rows, summary = build_consensus_rows_and_summary(clusters, total_tools=len(ctx.tools))

    store.put(StoreKeys.CONSENSUS_ROWS, rows)
    store.put(StoreKeys.CONSENSUS_SUMMARY, summary)

    out_json = Path(ctx.out_dir) / "consensus_queue.json"
    out_csv = Path(ctx.out_dir) / "consensus_queue.csv"

    if "json" in ctx.formats:
        write_json(out_json, {"summary": summary, "rows": rows})
        store.add_artifact("consensus_queue_json", out_json)
    if "csv" in ctx.formats:
        write_csv(
            out_csv,
            rows,
            fieldnames=[
                "rank",
                "file_path",
                "start_line",
                "end_line",
                "tool_count",
                "agreement_fraction",
                "consensus_level",
                "tools",
                "total_findings",
                "max_severity",
                "sample_rule_id",
                "sample_title",
                "cluster_id",
            ],
        )
        store.add_artifact("consensus_queue_csv", out_csv)

    return summary
