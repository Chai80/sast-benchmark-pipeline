from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from pipeline.analysis.compute.overview import analyze_latest_hotspots_for_repo, print_text_report
from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_json

from ..common.store_keys import StoreKeys


@register_stage(
    "overview",
    kind="analysis",
    description="Compute per-file overlap + unique-file summary across tools.",
    produces=(StoreKeys.OVERVIEW_REPORT,),
)
def stage_overview(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    report = analyze_latest_hotspots_for_repo(
        repo_name=ctx.repo_name,
        tools=ctx.tools,
        runs_dir=ctx.runs_dir,
        mode=ctx.mode,
        exclude_prefixes=getattr(ctx, "exclude_prefixes", ()) or (),
    )
    store.put(StoreKeys.OVERVIEW_REPORT, report)

    out_path = Path(ctx.out_dir) / "latest_hotspots_by_file.json"
    write_json(out_path, report)
    store.add_artifact("latest_hotspots_by_file", out_path)

    return {
        "tools": report.get("tools") or [],
        "files": len(report.get("files") or []),
    }
