from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_json
from pipeline.analysis.stages.common.locations import ensure_location_clusters
from pipeline.analysis.stages.common.severity import max_severity
from pipeline.analysis.stages.common.store_keys import StoreKeys


def build_hotspot_drilldown_pack(ctx: AnalysisContext, store: ArtifactStore, *, limit: int = 200) -> Dict[str, Any]:
    clusters = ensure_location_clusters(ctx, store)

    out_rows: List[Dict[str, Any]] = []
    for c in clusters[: max(0, int(limit))]:
        items = list(c.get("items") or [])
        sev, _rank = max_severity(items)
        # Small, human-friendly subset of findings per cluster.
        examples = []
        for it in items[:5]:
            examples.append(
                {
                    "tool": it.get("tool"),
                    "severity": it.get("severity"),
                    "rule_id": it.get("rule_id"),
                    "title": it.get("title"),
                    "finding_id": it.get("finding_id"),
                }
            )

        out_rows.append(
            {
                "cluster_id": c.get("cluster_id"),
                "file_path": c.get("file_path"),
                "start_line": c.get("start_line"),
                "end_line": c.get("end_line"),
                "tools": c.get("tools") or [],
                "tool_count": c.get("tool_count") or 0,
                "max_severity": sev,
                "examples": examples,
            }
        )

    return {
        "schema_version": "hotspot_drilldown_pack_v1",
        "context": {
            "suite_id": ctx.suite_id,
            "case_id": ctx.case_id,
            "repo_name": ctx.repo_name,
            "tools": list(ctx.tools),
            "mode": ctx.mode,
            "tolerance": ctx.tolerance,
        },
        "hotspots": out_rows,
    }


@register_stage(
    "hotspot_drilldown_pack",
    kind="reporting",
    description="Write hotspot_drilldown_pack.json (top-N hotspots with example findings).",
)
def stage_drilldown_pack(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    pack = build_hotspot_drilldown_pack(ctx, store, limit=200)
    out_path = Path(ctx.out_dir) / "hotspot_drilldown_pack.json"
    write_json(out_path, pack)
    store.add_artifact("hotspot_drilldown_pack", out_path)
    store.put(StoreKeys.HOTSPOT_DRILLDOWN_PACK, pack)
    return {"hotspots": len(pack.get("hotspots") or [])}


def main(argv: List[str] | None = None) -> None:  # pragma: no cover
    ap = argparse.ArgumentParser(description="Build hotspot drilldown pack from an analysis directory.")
    ap.add_argument("--analysis-dir", required=True)
    args = ap.parse_args(argv)

    p = Path(args.analysis_dir) / "hotspot_drilldown_pack.json"
    if p.exists():
        print(p.read_text(encoding="utf-8"))
        return
    raise SystemExit(f"hotspot_drilldown_pack.json not found in: {args.analysis_dir}")
