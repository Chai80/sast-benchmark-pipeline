from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from pipeline.analysis.compute.taxonomy import (
    build_taxonomy_rows,
    load_cwe_to_owasp_map,
)
from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json

from ..common.findings import load_findings_by_tool
from ..common.store_keys import StoreKeys


@register_stage(
    "taxonomy",
    kind="analysis",
    description="Derive OWASP Top10 categories (canonical via CWE) and write taxonomy counts.",
    requires=(StoreKeys.FINDINGS_BY_TOOL,),
    produces=(StoreKeys.CWE_TO_OWASP_MAP, StoreKeys.TAXONOMY_ROWS),
)
def stage_taxonomy(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    fb = load_findings_by_tool(ctx, store)

    cwe_map = store.get(StoreKeys.CWE_TO_OWASP_MAP)
    if not isinstance(cwe_map, dict) or not cwe_map:
        cwe_map = load_cwe_to_owasp_map()
        store.put(StoreKeys.CWE_TO_OWASP_MAP, cwe_map)

    rows = build_taxonomy_rows(fb, cwe_to_owasp_map=cwe_map)
    store.put(StoreKeys.TAXONOMY_ROWS, rows)

    out_csv = Path(ctx.out_dir) / "taxonomy_analysis.csv"
    out_json = Path(ctx.out_dir) / "taxonomy_analysis.json"
    if "csv" in ctx.formats:
        write_csv(
            out_csv,
            rows,
            fieldnames=["tool", "owasp_2021_code", "count", "tool_total_findings"],
        )
        store.add_artifact("taxonomy_analysis_csv", out_csv)
    if "json" in ctx.formats:
        write_json(out_json, rows)
        store.add_artifact("taxonomy_analysis_json", out_json)

    return {"rows": len(rows)}
