from __future__ import annotations

"""Tool profile computations.

Given findings grouped by tool, compute a per-tool summary table.
"""

from collections import Counter
from typing import Any, Dict, List, Mapping


def build_tool_profile_rows(
    findings_by_tool: Mapping[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """Build tool profile rows.

    Output schema matches `tool_profile.csv` / `tool_profile.json`.
    """

    rows: List[Dict[str, Any]] = []
    for tool, findings in findings_by_tool.items():
        sev = Counter(
            str(f.get("severity") or "").upper().strip()
            for f in findings
            if isinstance(f, dict)
        )

        files = set()
        for f in findings:
            if not isinstance(f, dict):
                continue
            fp = str(f.get("file_path") or "")
            if fp:
                files.add(fp)

        # Normalized issue types (if present)
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
                "types": ",".join([f"{k}:{v}" for k, v in types.most_common()])
                if types
                else "",
            }
        )

    rows.sort(key=lambda r: r.get("tool"))
    return rows
