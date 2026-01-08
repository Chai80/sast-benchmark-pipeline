from __future__ import annotations

from typing import Any, Dict, Iterable, List


def is_security_finding(tool: str, finding: Dict[str, Any]) -> bool:
    """Best-effort filter to keep only security-relevant findings.

    This is primarily important for Sonar, which reports many CODE_SMELL issues.
    """
    t = (tool or "").lower()
    if t == "sonar":
        raw = (finding.get("vendor") or {}).get("raw_result") or {}
        if isinstance(raw, dict):
            issue_type = str(raw.get("type") or "").upper()
            return issue_type in {"VULNERABILITY", "SECURITY_HOTSPOT"}
        return False

    if t == "semgrep":
        raw = (finding.get("vendor") or {}).get("raw_result") or {}
        if isinstance(raw, dict):
            extra = raw.get("extra") or {}
            if isinstance(extra, dict):
                meta = extra.get("metadata") or {}
                if isinstance(meta, dict):
                    cat = str(meta.get("category") or "").lower()
                    if cat:
                        return cat == "security"
        # If Semgrep didn't provide category metadata, treat it as security.
        return True

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
