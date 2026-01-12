"""tools/sonar/normalize.py

Normalization for SonarCloud issues into the common schema v1.1.

This module MUST use package imports (tools.*) so it works when scan_sonar.py
is invoked either as a module (python -m ...) or as a script.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from tools.normalize.common import (
    build_per_finding_metadata,
    build_scan_info,
    build_target_repo,
)
from tools.io import read_line_content, write_json

from tools.core import finalize_normalized_findings

from .api import fetch_rule_show
from .rules import parse_rule_classification
from .types import SonarConfig


def map_sonar_severity(severity_raw: Optional[str]) -> Optional[str]:
    sev = (severity_raw or "").upper()
    if sev in ("BLOCKER", "CRITICAL", "MAJOR"):
        return "HIGH"
    if sev == "MINOR":
        return "MEDIUM"
    if sev == "INFO":
        return "LOW"
    return None


def extract_location(issue: Dict[str, Any]) -> Tuple[Optional[str], Optional[int], Optional[int]]:
    component = issue.get("component") or ""
    file_path: Optional[str] = None
    if component:
        file_path = component.split(":", 1)[1] if ":" in component else component

    line = issue.get("line")
    text_range = issue.get("textRange") or {}
    if line is None:
        line = text_range.get("startLine")
    end_line = text_range.get("endLine", line)
    return file_path, line, end_line


def normalize_one_issue_base(
    *,
    issue: Dict[str, Any],
    repo_path: Path,
    per_finding_metadata: Dict[str, Any],
) -> Dict[str, Any]:
    rule_id = issue.get("rule")
    title = issue.get("message")
    severity = map_sonar_severity(issue.get("severity"))

    # Sonar issue type is important for filtering CODE_SMELL vs security.
    issue_type_raw = issue.get("type")
    issue_type = str(issue_type_raw).upper().strip() if isinstance(issue_type_raw, str) else None

    file_path, line, end_line = extract_location(issue)

    return {
        "metadata": per_finding_metadata,
        "finding_id": f"sonar:{rule_id}:{file_path}:{line}",
        "cwe_id": None,
        "cwe_ids": [],
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "issue_type": issue_type,
        "file_path": file_path,
        "line_number": line,
        "end_line_number": end_line,
        "line_content": read_line_content(repo_path, file_path, line),
        "vuln_class": None,
        "owasp_top_10_2017": None,
        "owasp_top_10_2021": None,
        "vendor": {"raw_result": issue},
    }


def apply_rule_enrichment(
    *,
    finding: Dict[str, Any],
    classification: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if not classification:
        return finding

    cwe_ids = classification.get("cwe_ids") or []
    if cwe_ids:
        finding["cwe_ids"] = cwe_ids
        if not finding.get("cwe_id"):
            finding["cwe_id"] = cwe_ids[0]

    vuln_class = classification.get("vuln_class")
    if vuln_class:
        finding["vuln_class"] = vuln_class

    o2017 = classification.get("owasp_top_10_2017")
    if o2017:
        finding["owasp_top_10_2017"] = o2017

    o2021 = classification.get("owasp_top_10_2021")
    if o2021:
        finding["owasp_top_10_2021"] = o2021

    return finding


def build_rule_cache(cfg: SonarConfig, rule_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    cache: Dict[str, Dict[str, Any]] = {}
    for rid in rule_ids:
        raw = fetch_rule_show(cfg, rid)
        if not raw:
            continue
        cls = parse_rule_classification(rule_key=rid, rules_show_json=raw)
        if cls:
            cache[rid] = cls
    return cache


def normalize_sonar_results(
    *,
    repo_path: Path,
    raw_results_path: Path,
    metadata: Dict[str, Any],
    normalized_path: Path,
    cfg: SonarConfig,
) -> None:
    target_repo = build_target_repo(metadata)
    scan_info = build_scan_info(metadata, raw_results_path)
    per_finding_metadata = build_per_finding_metadata(
        tool="sonar",
        tool_version=metadata.get("scanner_version"),
        target_repo=target_repo,
        scan_info=scan_info,
    )

    if not raw_results_path.exists():
        write_json(
            normalized_path,
            {
                "schema_version": "1.1",
                "tool": "sonar",
                "tool_version": metadata.get("scanner_version"),
                "target_repo": target_repo,
                "scan": scan_info,
                "run_metadata": metadata,
                "findings": [],
            },
        )
        return

    with raw_results_path.open(encoding="utf-8") as f:
        data = json.load(f)

    issues = data.get("issues") or []

    seen: Set[str] = set()
    rule_ids: List[str] = []
    for issue in issues:
        rid = issue.get("rule")
        if isinstance(rid, str) and rid not in seen:
            seen.add(rid)
            rule_ids.append(rid)

    rule_cache = build_rule_cache(cfg, rule_ids)

    findings: List[Dict[str, Any]] = []
    enriched_count = 0

    for issue in issues:
        base = normalize_one_issue_base(
            issue=issue,
            repo_path=repo_path,
            per_finding_metadata=per_finding_metadata,
        )
        rid = base.get("rule_id")
        cls = rule_cache.get(rid) if isinstance(rid, str) else None
        if cls:
            enriched_count += 1
        findings.append(apply_rule_enrichment(finding=base, classification=cls))

    findings = finalize_normalized_findings(findings)

    write_json(
        normalized_path,
        {
            "schema_version": "1.1",
            "tool": "sonar",
            "tool_version": metadata.get("scanner_version"),
            "target_repo": target_repo,
            "scan": scan_info,
            "run_metadata": metadata,
            "sonar_rules_enrichment": {
                "source": "api/rules/show",
                "host": cfg.host,
                "organization": cfg.org,
                "rules_with_classification": len(rule_cache),
                "findings_enriched": enriched_count,
            },
            "findings": findings,
        },
    )
