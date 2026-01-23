from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from pipeline.analysis.compute.tool_profile import build_tool_profile_rows
from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json

from ..common.findings import load_findings_by_tool
from ..common.store_keys import StoreKeys


@register_stage(
    "tool_profile",
    kind="analysis",
    description="Summarize finding counts and severity distribution per tool.",
    produces=(StoreKeys.FINDINGS_BY_TOOL, StoreKeys.TOOL_PROFILE_ROWS),
)
def stage_tool_profile(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    fb = load_findings_by_tool(ctx, store)
    rows = build_tool_profile_rows(fb)

    store.put(StoreKeys.TOOL_PROFILE_ROWS, rows)

    out_json = Path(ctx.out_dir) / "tool_profile.json"
    out_csv = Path(ctx.out_dir) / "tool_profile.csv"

    if "json" in ctx.formats:
        write_json(out_json, rows)
        store.add_artifact("tool_profile_json", out_json)
    if "csv" in ctx.formats:
        write_csv(out_csv, rows, fieldnames=["tool", "findings", "files", "high", "medium", "low", "unknown", "types"])
        store.add_artifact("tool_profile_csv", out_csv)

    return {"tools": len(rows)}
