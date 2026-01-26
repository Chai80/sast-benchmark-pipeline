from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_json

from ..common.findings import load_findings_by_tool
from ..common.store_keys import StoreKeys


@register_stage(
    "diagnostics_empty_runs",
    kind="diagnostic",
    description="Detect tools with zero findings (after filtering).",
    produces=(StoreKeys.FINDINGS_BY_TOOL, StoreKeys.DIAGNOSTICS_EMPTY_RUNS),
)
def stage_diagnostics_empty(
    ctx: AnalysisContext, store: ArtifactStore
) -> Dict[str, Any]:
    fb = load_findings_by_tool(ctx, store)
    empties = [tool for tool, findings in fb.items() if not findings]
    report = {"tools": list(ctx.tools), "empty_tools": empties}

    out_path = Path(ctx.out_dir) / "diagnostics_empty_runs.json"
    write_json(out_path, report)
    store.add_artifact("diagnostics_empty_runs", out_path)
    store.put(StoreKeys.DIAGNOSTICS_EMPTY_RUNS, report)
    return {"empty_tools": len(empties)}
