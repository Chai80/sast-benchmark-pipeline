"""tools/semgrep/normalize.py

Semgrep-specific normalization into the repo's normalized schema (v1.1).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pathlib import Path

from tools.core import (
    load_cwe_to_owasp_map,
    finalize_normalized_findings,
    normalize_repo_relative_path,
    read_json,
    read_line_content,
    write_json,
)
from tools.normalize.common import (
    build_per_finding_metadata,
    build_scan_info,
    build_target_repo,
)
from tools.normalize.extractors import extract_cwe_candidates, extract_location
from tools.normalize.classification import resolve_owasp_and_cwe


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def map_semgrep_severity(sev: Optional[str]) -> Optional[str]:
    if sev is None:
        return None
    s = str(sev).strip().upper()
    if s in {"ERROR", "CRITICAL"}:
        return "HIGH"
    if s == "WARNING":
        return "MEDIUM"
    if s == "INFO":
        return "LOW"
    if s in {"HIGH", "MEDIUM", "LOW"}:
        return s
    return "MEDIUM"


def normalize_semgrep_results(
    *,
    repo_path: Path,
    raw_results_path: Path,
    metadata: Dict[str, Any],
    normalized_path: Path,
) -> None:
    target_repo = build_target_repo(metadata)
    scan_info = build_scan_info(metadata, raw_results_path)
    per_finding_metadata = build_per_finding_metadata(
        tool="semgrep",
        tool_version=metadata.get("scanner_version"),
        target_repo=target_repo,
        scan_info=scan_info,
    )

    if not raw_results_path.exists():
        write_json(
            normalized_path,
            {
                "schema_version": "1.1",
                "tool": "semgrep",
                "tool_version": metadata.get("scanner_version"),
                "target_repo": target_repo,
                "scan": scan_info,
                "run_metadata": metadata,
                "findings": [],
            },
        )
        return

    raw = read_json(raw_results_path)
    results = (raw or {}).get("results") or []
    if not isinstance(results, list):
        results = []

    cwe_to_owasp_map = load_cwe_to_owasp_map()
    findings: List[Dict[str, Any]] = []

    for res in results:
        if not isinstance(res, dict):
            continue

        check_id = res.get("check_id") or res.get("rule_id") or res.get("id")
        rule_id = str(check_id) if check_id is not None else "unknown"

        extra = res.get("extra") or {}
        message = None
        if isinstance(extra, dict) and isinstance(extra.get("message"), str):
            message = extra.get("message")
        if not message and isinstance(res.get("message"), str):
            message = res.get("message")
        title = (message or rule_id).strip() if isinstance(message, str) else rule_id

        sev_raw = None
        if isinstance(extra, dict):
            sev_raw = extra.get("severity") or (extra.get("metadata") or {}).get("severity")
        sev = map_semgrep_severity(sev_raw)

        loc = extract_location(res, tool="semgrep")
        file_path = (
            normalize_repo_relative_path(repo_path, loc.file_path) if loc.file_path else None
        )
        line = loc.line_number
        end_line = loc.end_line_number

        line_content = read_line_content(repo_path, file_path, line)

        meta = {}
        if isinstance(extra, dict):
            meta = extra.get("metadata") or {}
            if not isinstance(meta, dict):
                meta = {}

        # Normalized issue type used by analysis filtering.
        # Semgrep rules sometimes tag findings with metadata.category=security.
        # If category is missing, treat Semgrep as security-by-default.
        cat_raw = meta.get("category")
        cat: Optional[str] = None
        if isinstance(cat_raw, str):
            cat = cat_raw.strip()
        elif isinstance(cat_raw, list) and cat_raw:
            first = cat_raw[0]
            if isinstance(first, str):
                cat = first.strip()
        issue_type = cat.upper() if cat else "SECURITY"

        semgrep_owasp_tags = _as_list(meta.get("owasp")) or _as_list(meta.get("owasp_top_10"))
        vuln_class_list = _as_list(meta.get("vulnerability_class"))
        vuln_class = str(vuln_class_list[0]) if vuln_class_list else None

        cwe_candidates = extract_cwe_candidates(meta) or _as_list(meta.get("cwe"))

        tags: List[str] = []
        tags += [str(x) for x in semgrep_owasp_tags if x is not None]
        tags += [str(x) for x in vuln_class_list if x is not None]
        tags += [str(x) for x in _as_list(meta.get("category")) if x is not None]
        tags += [str(x) for x in _as_list(meta.get("technology")) if x is not None]
        tags += [str(x) for x in _as_list(meta.get("subcategory")) if x is not None]

        classification = resolve_owasp_and_cwe(
            tags=tags,
            cwe_candidates=cwe_candidates,
            cwe_to_owasp_map=cwe_to_owasp_map,
            vendor_owasp_2021_codes=None,
            allow_2017_from_tags=True,
        )

        finding_id = f"semgrep:{rule_id}:{file_path}:{line}"

        findings.append(
            {
                "metadata": per_finding_metadata,
                "finding_id": finding_id,
                "rule_id": rule_id,
                "title": title,
                "severity": sev,
                "issue_type": issue_type,
                "file_path": file_path,
                "line_number": line,
                "end_line_number": end_line,
                "line_content": line_content,
                **classification,
                "vuln_class": vuln_class,
                "vendor": {"raw_result": res},
            }
        )

    findings = finalize_normalized_findings(findings)

    write_json(
        normalized_path,
        {
            "schema_version": "1.1",
            "tool": "semgrep",
            "tool_version": metadata.get("scanner_version"),
            "target_repo": target_repo,
            "scan": scan_info,
            "run_metadata": metadata,
            "findings": findings,
        },
    )
