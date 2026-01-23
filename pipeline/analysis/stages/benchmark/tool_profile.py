from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json

from ..common.findings import load_findings_by_tool
from ..common.severity import severity_rank
from ..common.store_keys import StoreKeys


@register_stage(
    "tool_profile",
    kind="analysis",
    description="Summarize finding counts and severity distribution per tool.",
    produces=(StoreKeys.FINDINGS_BY_TOOL, StoreKeys.TOOL_PROFILE_ROWS),
)
def stage_tool_profile(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    fb = load_findings_by_tool(ctx, store)

    rows: List[Dict[str, Any]] = []
    for tool, findings in fb.items():
        sev = Counter(str(f.get("severity") or "").upper().strip() for f in findings if isinstance(f, dict))
        files = set()
        for f in findings:
            if not isinstance(f, dict):
                continue
            fp = str(f.get("file_path") or "")
            if fp:
                files.add(fp)
        # Issue types (normalized field)
        types = Counter()
        for f in findings:
            if not isinstance(f, dict):
                continue
            it = f.get("issue_type")
            if isinstance(it, str) and it.strip():
                types[it.strip().upper()] += 1

        rows.append(
            {
                "tool": tool,
                "findings": len(findings),
                "files": len(files),
                "high": int(sev.get("HIGH", 0)),
                "medium": int(sev.get("MEDIUM", 0)),
                "low": int(sev.get("LOW", 0)),
                "unknown": int(sev.get("", 0)),
                "types": ",".join([f"{k}:{v}" for k, v in types.most_common()]) if types else "",
            }
        )

    rows.sort(key=lambda r: r.get("tool"))

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

