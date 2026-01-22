from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json

from ..common.locations import ensure_location_clusters
from ..common.severity import max_severity
from ..common.store_keys import StoreKeys


@register_stage(
    "hotspot_matrix",
    kind="analysis",
    description="Rank clustered locations (hotspots) by cross-tool agreement.",
)
def stage_hotspot_matrix(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    clusters = ensure_location_clusters(ctx, store)

    tools = list(ctx.tools)

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
                **{f"{t}_count": int(tool_counts.get(t, 0)) for t in tools},
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
        ] + [f"{t}_count" for t in tools]
        write_csv(out_csv, rows, fieldnames=fieldnames)
        store.add_artifact("hotspot_matrix_csv", out_csv)

    return {"hotspots": len(rows)}

