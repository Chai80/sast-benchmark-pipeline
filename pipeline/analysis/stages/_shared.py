from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from pipeline.analysis.framework import AnalysisContext, ArtifactStore
from pipeline.analysis.utils.filters import filter_findings
from pipeline.analysis.utils.path_norm import is_excluded_path, normalize_file_path


def load_normalized_json(path: Path) -> Dict[str, Any]:
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8"))


 


def load_findings_by_tool(ctx: AnalysisContext, store: ArtifactStore) -> Mapping[str, List[Dict[str, Any]]]:
    """Load + filter findings for each tool (cached in store).

    Filtering order:
      1) mode filter (security vs all)
      2) scope filter (exclude_prefixes)
    """
    cached = store.get("findings_by_tool")
    if isinstance(cached, dict):
        return cached

    findings_by_tool: Dict[str, List[Dict[str, Any]]] = {}
    for tool in ctx.tools:
        p = (ctx.normalized_paths or {}).get(tool)
        if not p:
            continue
        data = load_normalized_json(p)
        findings = data.get("findings") or []
        if not isinstance(findings, list):
            findings = []

        # 1) Mode filter
        findings_f = filter_findings(tool, findings, mode=ctx.mode)

        # 2) Scope filter
        ex = getattr(ctx, "exclude_prefixes", ()) or ()
        if ex:
            before = len(findings_f)
            findings_f = [
                f
                for f in findings_f
                if isinstance(f, dict)
                and not is_excluded_path(
                    str(f.get("file_path") or ""),
                    repo_name=ctx.repo_name,
                    exclude_prefixes=ex,
                )
            ]

            removed = before - len(findings_f)
            if removed:
                # Low-noise breadcrumb for later debugging.
                store.put(
                    "scope_filter_counts",
                    {
                        **(store.get("scope_filter_counts") or {}),
                        tool: {
                            "removed": int(removed),
                            "kept": int(len(findings_f)),
                        },
                    },
                )

        findings_by_tool[tool] = findings_f

    store.put("findings_by_tool", findings_by_tool)
    return findings_by_tool


def build_location_items(ctx: AnalysisContext, store: ArtifactStore) -> List[Dict[str, Any]]:
    """Flatten findings into a list of location items for clustering."""
    cached = store.get("location_items")
    if isinstance(cached, list):
        return cached

    items: List[Dict[str, Any]] = []
    fb = load_findings_by_tool(ctx, store)

    for tool, findings in fb.items():
        for f in findings:
            if not isinstance(f, dict):
                continue
            fp = normalize_file_path(str(f.get("file_path") or ""), repo_name=ctx.repo_name)
            items.append(
                {
                    "tool": tool,
                    "finding_id": f.get("finding_id"),
                    "rule_id": f.get("rule_id"),
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "file_path": fp,
                    "line_number": f.get("line_number"),
                    "end_line_number": f.get("end_line_number"),
                    "vendor": f.get("vendor") or {},
                }
            )

    store.put("location_items", items)
    return items


def severity_rank(sev: Any) -> int:
    s = str(sev or "").upper().strip()
    if s == "HIGH":
        return 3
    if s == "MEDIUM":
        return 2
    if s == "LOW":
        return 1
    return 0


def max_severity(items: List[Dict[str, Any]]) -> Tuple[str, int]:
    best = ("", 0)
    for it in items or []:
        r = severity_rank(it.get("severity"))
        if r > best[1]:
            best = (str(it.get("severity") or ""), r)
    return best
