from __future__ import annotations

from typing import Any, Dict, Iterable, List


def is_security_finding(tool: str, finding: Dict[str, Any]) -> bool:
    """Best-effort filter to keep only security-relevant findings.

    This is primarily important for Sonar, which reports many CODE_SMELL issues.
    """
    t = (tool or "").lower()

    # Prefer normalized fields so analysis doesn't need to parse vendor objects.
    issue_type = str(finding.get("issue_type") or "").upper().strip()

    if t == "sonar":
        # Sonar emits many CODE_SMELL issues. Keep only security-relevant types.
        return issue_type in {"VULNERABILITY", "SECURITY_HOTSPOT"}

    if t == "semgrep":
        # Semgrep normalization sets issue_type from metadata.category when present.
        # If missing, Semgrep findings are treated as security-by-default.
        if not issue_type:
            return True
        return issue_type == "SECURITY"

    # Snyk / Aikido / others are security-by-design in this repo.
    return True


def filter_findings(tool: str, findings: Iterable[Dict[str, Any]], *, mode: str = "security") -> List[Dict[str, Any]]:
    mode = (mode or "security").lower().strip()
    out: List[Dict[str, Any]] = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        if mode == "all":
            out.append(f)
        else:
            if is_security_finding(tool, f):
                out.append(f)
    return out
