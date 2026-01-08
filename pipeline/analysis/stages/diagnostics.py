from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_json

from ._shared import load_findings_by_tool, load_normalized_json


def _load_normalized_by_tool(ctx: AnalysisContext) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for tool in ctx.tools:
        p = (ctx.normalized_paths or {}).get(tool)
        if not p:
            continue
        try:
            out[tool] = load_normalized_json(p)
        except Exception:
            out[tool] = {}
    return out


@register_stage(
    "diagnostics_schema",
    kind="diagnostic",
    description="Schema sanity checks for normalized JSON files.",
)
def stage_diagnostics_schema(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    normalized = _load_normalized_by_tool(ctx)

    missing_top = Counter()
    missing_finding = Counter()
    finding_counts = {}

    required_top = ["schema_version", "tool", "findings"]
    required_finding = ["finding_id", "rule_id", "title", "file_path", "line_number", "severity"]

    for tool, doc in normalized.items():
        finding_counts[tool] = len(doc.get("findings") or []) if isinstance(doc.get("findings"), list) else 0
        for k in required_top:
            if k not in doc:
                missing_top[k] += 1

        findings = doc.get("findings") or []
        if isinstance(findings, list):
            for f in findings[:200]:  # sample to keep it cheap
                if not isinstance(f, dict):
                    continue
                for k in required_finding:
                    if k not in f or f.get(k) in (None, ""):
                        missing_finding[k] += 1

    report = {
        "tools": list(ctx.tools),
        "files": {t: str((ctx.normalized_paths or {}).get(t) or "") for t in ctx.tools},
        "finding_counts": finding_counts,
        "missing_top_level_counts": dict(missing_top),
        "missing_finding_field_counts_sampled": dict(missing_finding),
    }

    out_path = Path(ctx.out_dir) / "diagnostics_schema.json"
    write_json(out_path, report)
    store.add_artifact("diagnostics_schema", out_path)
    store.put("diagnostics_schema", report)
    return {"tools": len(ctx.tools)}


@register_stage(
    "diagnostics_empty_runs",
    kind="diagnostic",
    description="Detect tools with zero findings (after filtering).",
)
def stage_diagnostics_empty(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    fb = load_findings_by_tool(ctx, store)
    empties = [tool for tool, findings in fb.items() if not findings]
    report = {"tools": list(ctx.tools), "empty_tools": empties}

    out_path = Path(ctx.out_dir) / "diagnostics_empty_runs.json"
    write_json(out_path, report)
    store.add_artifact("diagnostics_empty_runs", out_path)
    store.put("diagnostics_empty_runs", report)
    return {"empty_tools": len(empties)}
