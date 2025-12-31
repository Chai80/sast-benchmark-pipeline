"""tools/aikido/normalize.py

Aikido issues JSON -> normalized schema (v1.1).

Design note
-----------
This normalizer is intentionally thin.

* Tool-specific fields (how to get rule_id/title for Aikido) live here.
* Boring, cross-tool parsing (location/severity/CWE candidates/tag collection)
  lives in :mod:`tools.normalize.extractors`.

That keeps each tool normalizer from re-implementing the same helpers and
reduces "spaghetti" risk as the project grows.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.core import load_cwe_to_owasp_map
from tools.io import read_json, write_json
from tools.normalize.classification import resolve_owasp_and_cwe
from tools.normalize.common import build_per_finding_metadata, build_scan_info, build_target_repo
from tools.normalize.extractors import (
    collect_tags_and_text,
    extract_cwe_candidates,
    extract_location,
    extract_vendor_owasp_2021_codes,
    map_severity,
)


def _extract_rule_id(issue: Dict[str, Any]) -> Optional[str]:
    """Best-effort extract of the Aikido "rule" identifier."""
    for k in ("rule_id", "rule", "type", "category"):
        v = issue.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if v is not None and not isinstance(v, (dict, list)):
            return str(v)
    return None


def _extract_title(issue: Dict[str, Any], issue_id: Any) -> Optional[str]:
    """Best-effort extract of a human-friendly title."""
    for k in ("title", "summary", "message", "name"):
        v = issue.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    if issue_id is not None:
        return f"Aikido issue {issue_id}"
    return None


def _extract_raw_severity(issue: Dict[str, Any]) -> Any:
    """Pick a likely severity field from the vendor payload."""
    # Aikido exports typically include "severity" and sometimes "severity_score".
    # Keep this logic here (tool-specific); mapping is handled by extractors.map_severity.
    return issue.get("severity") or issue.get("risk") or issue.get("level") or issue.get("severity_score")


def _build_finding(
    *,
    issue: Dict[str, Any],
    per_finding_metadata: Dict[str, Any],
    cwe_to_owasp_map: Dict[str, Any],
) -> Dict[str, Any]:
    issue_id = issue.get("id")

    rule_id = _extract_rule_id(issue)
    title = _extract_title(issue, issue_id)

    severity = map_severity(_extract_raw_severity(issue), tool="aikido")

    loc = extract_location(issue, tool="aikido")
    file_path = loc.file_path
    line = loc.line_number
    end_line = loc.end_line_number or line

    tags = collect_tags_and_text(issue, tool="aikido")
    cwe_candidates = extract_cwe_candidates(issue)
    vendor_owasp_2021 = extract_vendor_owasp_2021_codes(issue)

    classification = resolve_owasp_and_cwe(
        tags=tags,
        cwe_candidates=cwe_candidates,
        cwe_to_owasp_map=cwe_to_owasp_map,
        vendor_owasp_2021_codes=vendor_owasp_2021 or None,
        allow_2017_from_tags=True,
    )

    stable_parts = [
        str(issue_id) if issue_id is not None else None,
        rule_id,
        file_path,
        str(line) if line is not None else None,
    ]
    stable = ":".join([p for p in stable_parts if p]) or "unknown"

    return {
        "metadata": per_finding_metadata,
        "finding_id": f"aikido:{stable}",
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "file_path": file_path,
        "line_number": line,
        "end_line_number": end_line,
        "line_content": None,
        **classification,
        "vendor": {"raw_result": issue},
    }


def _coerce_issues_payload(payload: Any) -> List[Dict[str, Any]]:
    """Accept multiple Aikido export shapes and return a list of issue dicts."""
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]

    # Some exports wrap the list under a "data" key.
    if isinstance(payload, dict) and isinstance(payload.get("data"), list):
        return [x for x in payload["data"] if isinstance(x, dict)]

    return []


def normalize_aikido_results(raw_results_path: Path, metadata: Dict[str, Any], normalized_path: Path) -> None:
    target_repo = build_target_repo(metadata)
    scan_info = build_scan_info(metadata, raw_results_path)
    per_finding_metadata = build_per_finding_metadata(
        tool="aikido",
        tool_version=metadata.get("scanner_version"),
        target_repo=target_repo,
        scan_info=scan_info,
    )

    if not raw_results_path.exists():
        write_json(
            normalized_path,
            {
                "schema_version": "1.1",
                "tool": "aikido",
                "tool_version": metadata.get("scanner_version"),
                "target_repo": target_repo,
                "scan": scan_info,
                "run_metadata": metadata,
                "findings": [],
            },
        )
        return

    issues_raw = read_json(raw_results_path)
    issues = _coerce_issues_payload(issues_raw)

    cwe_to_owasp_map = load_cwe_to_owasp_map()
    findings: List[Dict[str, Any]] = []

    for issue in issues:
        try:
            findings.append(
                _build_finding(
                    issue=issue,
                    per_finding_metadata=per_finding_metadata,
                    cwe_to_owasp_map=cwe_to_owasp_map,
                )
            )
        except Exception as e:
            # Never let a single weird issue object break the whole run.
            findings.append(
                {
                    "metadata": per_finding_metadata,
                    "finding_id": f"aikido:parse_error:{issue.get('id')}",
                    "rule_id": _extract_rule_id(issue),
                    "title": _extract_title(issue, issue.get("id")) or "Aikido issue (parse_error)",
                    "severity": map_severity(_extract_raw_severity(issue), tool="aikido"),
                    "file_path": None,
                    "line_number": None,
                    "end_line_number": None,
                    "line_content": None,
                    "cwe_id": None,
                    "cwe_ids": [],
                    "owasp_top_10_2017": None,
                    "owasp_top_10_2021": None,
                    "owasp_top_10_2017_vendor": None,
                    "owasp_top_10_2017_canonical": None,
                    "owasp_top_10_2021_vendor": None,
                    "owasp_top_10_2021_canonical": None,
                    "vendor": {"raw_result": issue, "parse_error": str(e)},
                }
            )

    write_json(
        normalized_path,
        {
            "schema_version": "1.1",
            "tool": "aikido",
            "tool_version": metadata.get("scanner_version"),
            "target_repo": target_repo,
            "scan": scan_info,
            "run_metadata": metadata,
            "findings": findings,
        },
    )
