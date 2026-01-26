from __future__ import annotations

"""Consensus computations.

Consensus (multi-tool agreement) scoring is intentionally GT-free.
It answers:
  "Which hotspots do multiple tools agree on?"

This module keeps the scoring logic out of the stage wrapper.
"""

from collections import Counter
from typing import Any, Dict, List, Sequence, Tuple

from pipeline.analysis.stages.common.severity import max_severity


def _sample_field(items: List[Dict[str, Any]], field: str) -> str:
    for it in items or []:
        v = it.get(field)
        if v:
            return str(v)
    return ""


def _consensus_level(tool_count: int, total_tools: int) -> str:
    if tool_count <= 0:
        return "none"
    if tool_count == 1:
        return "single"
    if total_tools > 0 and tool_count >= total_tools:
        return "unanimous"
    return "multi"


def build_consensus_rows_and_summary(
    clusters: Sequence[Dict[str, Any]], *, total_tools: int
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Compute consensus queue rows and a small summary."""

    rows: List[Dict[str, Any]] = []
    by_tool_count: Counter[int] = Counter()

    for c in clusters:
        items = list(c.get("items") or [])
        tool_count = int(c.get("tool_count") or 0)
        by_tool_count[tool_count] += 1

        sev, _rank = max_severity(items)
        rows.append(
            {
                "file_path": c.get("file_path"),
                "start_line": c.get("start_line"),
                "end_line": c.get("end_line"),
                "cluster_id": c.get("cluster_id"),
                "tools": ",".join(c.get("tools") or []),
                "tool_count": tool_count,
                "agreement_fraction": (tool_count / total_tools) if total_tools else 0.0,
                "consensus_level": _consensus_level(tool_count, total_tools),
                "total_findings": len(items),
                "max_severity": sev,
                "sample_rule_id": _sample_field(items, "rule_id"),
                "sample_title": _sample_field(items, "title"),
            }
        )

    def _sev_rank(row: Dict[str, Any]) -> int:
        s = str(row.get("max_severity") or "").upper().strip()
        if s == "HIGH":
            return 3
        if s == "MEDIUM":
            return 2
        if s == "LOW":
            return 1
        return 0

    rows.sort(
        key=lambda r: (
            -int(r.get("tool_count") or 0),
            -_sev_rank(r),
            -int(r.get("total_findings") or 0),
            str(r.get("file_path") or ""),
            int(r.get("start_line") or 0),
        )
    )
    for i, r in enumerate(rows, start=1):
        r["rank"] = i

    summary = {
        "clusters": len(rows),
        "tools": int(total_tools),
        "top_tool_count": int(rows[0]["tool_count"]) if rows else 0,
        "by_tool_count": {
            str(k): int(v) for k, v in sorted(by_tool_count.items(), key=lambda kv: kv[0])
        },
    }

    return rows, summary
