from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json

from ._shared import load_findings_by_tool, severity_rank


@register_stage(
    "tool_profile",
    kind="analysis",
    description="Summarize finding counts and severity distribution per tool.",
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

    store.put("tool_profile_rows", rows)

    out_json = Path(ctx.out_dir) / "tool_profile.json"
    out_csv = Path(ctx.out_dir) / "tool_profile.csv"
    if "json" in ctx.formats:
        write_json(out_json, rows)
        store.add_artifact("tool_profile_json", out_json)
    if "csv" in ctx.formats:
        write_csv(out_csv, rows, fieldnames=["tool", "findings", "files", "high", "medium", "low", "unknown", "types"])
        store.add_artifact("tool_profile_csv", out_csv)

    return {"tools": len(rows)}


def main(argv: List[str] | None = None) -> None:  # pragma: no cover
    ap = argparse.ArgumentParser(description="Build per-tool profile summary.")
    ap.add_argument("--in", dest="in_path", required=True, help="Path to a normalized JSON file (single tool)")
    ap.add_argument("--out", required=True, help="Output JSON path")
    args = ap.parse_args(argv)

    # Minimal helper: single-tool profiling.
    import json
    data = json.loads(Path(args.in_path).read_text(encoding="utf-8"))
    findings = data.get("findings") or []
    tool = data.get("tool") or "tool"
    sev = Counter(str(f.get("severity") or "").upper().strip() for f in findings if isinstance(f, dict))
    out = {
        "tool": tool,
        "findings": len(findings),
        "high": int(sev.get("HIGH", 0)),
        "medium": int(sev.get("MEDIUM", 0)),
        "low": int(sev.get("LOW", 0)),
    }
    Path(args.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
