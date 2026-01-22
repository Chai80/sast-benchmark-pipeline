from __future__ import annotations

"""pipeline.analysis.stages.common.findings

Helpers for loading normalized findings and caching them in the ArtifactStore.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping

from pipeline.analysis.framework import AnalysisContext, ArtifactStore
from pipeline.analysis.utils.filters import filter_findings
from pipeline.analysis.utils.path_norm import is_excluded_path

from .store_keys import StoreKeys


def load_normalized_json(path: Path) -> Dict[str, Any]:
    """Load a normalized JSON document from disk."""
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8"))


def load_findings_by_tool(ctx: AnalysisContext, store: ArtifactStore) -> Mapping[str, List[Dict[str, Any]]]:
    """Load + filter findings for each tool (cached in store).

    Filtering order:
      1) mode filter (security vs all)
      2) scope filter (exclude_prefixes)
    """
    cached = store.get(StoreKeys.FINDINGS_BY_TOOL)
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
                    StoreKeys.SCOPE_FILTER_COUNTS,
                    {
                        **(store.get(StoreKeys.SCOPE_FILTER_COUNTS) or {}),
                        tool: {
                            "removed": int(removed),
                            "kept": int(len(findings_f)),
                        },
                    },
                )

        findings_by_tool[tool] = findings_f

    store.put(StoreKeys.FINDINGS_BY_TOOL, findings_by_tool)
    return findings_by_tool
