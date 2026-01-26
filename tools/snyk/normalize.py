"""tools/snyk/normalize.py

Snyk SARIF -> normalized schema (v1.1).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from tools.core import (
    finalize_normalized_findings,
    load_cwe_to_owasp_map,
    read_json,
    write_json,
)
from tools.normalize.common import (
    build_per_finding_metadata,
    build_scan_info,
    build_target_repo,
)
from tools.normalize.classification import resolve_owasp_and_cwe

from .sarif import (
    extract_cwe_candidates,
    extract_tags,
    primary_location,
    rules_by_id,
    rule_name,
    severity_from_level,
)
from .vendor_rules import VendorRuleIndex, vendor_rule_info


def normalize_sarif(
    *,
    repo_path: Path,
    raw_sarif_path: Path,
    metadata: Dict[str, Any],
    vendor_idx: VendorRuleIndex,
    normalized_path: Path,
) -> None:
    target_repo = build_target_repo(metadata)
    scan_info = build_scan_info(metadata, raw_sarif_path)
    per_finding_metadata = build_per_finding_metadata(
        tool="snyk",
        tool_version=metadata.get("scanner_version"),
        target_repo=target_repo,
        scan_info=scan_info,
    )

    if not raw_sarif_path.exists():
        write_json(
            normalized_path,
            {
                "schema_version": "1.1",
                "tool": "snyk",
                "tool_version": metadata.get("scanner_version"),
                "target_repo": target_repo,
                "scan": scan_info,
                "run_metadata": metadata,
                "findings": [],
            },
        )
        return

    sarif = read_json(raw_sarif_path)
    runs = sarif.get("runs") or []
    run0 = runs[0] if isinstance(runs, list) and runs and isinstance(runs[0], dict) else {}
    rmap = rules_by_id(run0)
    results = run0.get("results") or []

    cwe_to_owasp_map = load_cwe_to_owasp_map()
    findings: List[Dict[str, Any]] = []

    for res in results if isinstance(results, list) else []:
        if not isinstance(res, dict):
            continue

        rid = res.get("ruleId") if isinstance(res.get("ruleId"), str) else None
        rdef = rmap.get(rid) if rid else None
        rname = rule_name(rdef)

        fp, start, end, line_content = primary_location(repo_path, res)
        sev = severity_from_level(res.get("level"))
        msg = res.get("message")
        title = (
            msg.get("text")
            if isinstance(msg, dict) and isinstance(msg.get("text"), str)
            else (rname or rid)
        )

        tags = extract_tags(rdef, res)
        cwe_candidates = extract_cwe_candidates(res, rdef, tags)

        vendor_codes, vendor_cwes = vendor_rule_info(vendor_idx, rid, rname)
        if vendor_cwes:
            cwe_candidates = cwe_candidates + vendor_cwes

        cls = resolve_owasp_and_cwe(
            tags=tags,
            cwe_candidates=cwe_candidates,
            vendor_owasp_2021_codes=vendor_codes,
            cwe_to_owasp_map=cwe_to_owasp_map,
            allow_2017_from_tags=True,
        )

        findings.append(
            {
                "metadata": per_finding_metadata,
                "finding_id": f"snyk:{rid}:{fp}:{start}",
                "rule_id": rid,
                "title": title,
                "severity": sev,
                "issue_type": "VULNERABILITY",
                "file_path": fp,
                "line_number": start,
                "end_line_number": end,
                "line_content": line_content,
                **cls,
                "vuln_class": None,
                "vendor": {"raw_result": res},
            }
        )

    findings = finalize_normalized_findings(findings)

    write_json(
        normalized_path,
        {
            "schema_version": "1.1",
            "tool": "snyk",
            "tool_version": metadata.get("scanner_version"),
            "target_repo": target_repo,
            "scan": scan_info,
            "run_metadata": metadata,
            "findings": findings,
        },
    )
