"""tools/aikido/normalize.py

Aikido issues JSON -> normalized schema (v1.1).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tools.core import load_cwe_to_owasp_map, write_json
from tools.normalize.common import build_per_finding_metadata, build_scan_info, build_target_repo
from tools.normalize.classification import resolve_owasp_and_cwe


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _coerce_int(x: Any) -> Optional[int]:
    try:
        if x is None:
            return None
        if isinstance(x, bool):
            return None
        return int(x)
    except Exception:
        return None


def _map_severity(issue: Dict[str, Any]) -> Optional[str]:
    raw = (issue.get("severity") or issue.get("risk") or issue.get("level") or "")
    s = str(raw).strip().upper()
    if s in {"CRITICAL", "HIGH"}:
        return "HIGH"
    if s in {"MEDIUM", "MODERATE"}:
        return "MEDIUM"
    if s in {"LOW", "INFO", "INFORMATIONAL"}:
        return "LOW"
    return None


def _extract_rule_id(issue: Dict[str, Any]) -> Optional[str]:
    for k in ("rule_id", "rule", "type", "category"):
        v = issue.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if v is not None and not isinstance(v, (dict, list)):
            return str(v)
    return None


def _extract_title(issue: Dict[str, Any], issue_id: Any) -> Optional[str]:
    for k in ("title", "summary", "message", "name"):
        v = issue.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    if issue_id is not None:
        return f"Aikido issue {issue_id}"
    return None


def _extract_location(issue: Dict[str, Any]) -> Tuple[Optional[str], Optional[int], Optional[int]]:
    file_path = (
        issue.get("file_path")
        or issue.get("file")
        or issue.get("path")
        or issue.get("affected_file")
        or issue.get("affectedFile")
    )
    line = issue.get("line") or issue.get("line_number") or issue.get("start_line")
    end_line = issue.get("end_line") or issue.get("end_line_number") or issue.get("endLine")

    loc = issue.get("location") or issue.get("source_location")
    if isinstance(loc, dict):
        file_path = (
            file_path
            or loc.get("file_path")
            or loc.get("file")
            or loc.get("path")
            or loc.get("affected_file")
            or loc.get("affectedFile")
        )
        line = line or loc.get("line") or loc.get("line_number") or loc.get("start_line")
        end_line = end_line or loc.get("end_line") or loc.get("end_line_number")

    line_i = _coerce_int(line)
    end_i = _coerce_int(end_line) or line_i
    return (str(file_path) if file_path else None, line_i, end_i)


def _extract_vendor_owasp_2021_codes(issue: Dict[str, Any]) -> List[str]:
    candidates: List[Any] = []
    for k in ("owasp_top_10_2021", "owasp_2021", "owasp2021", "owaspTop10_2021"):
        candidates.extend(_as_list(issue.get(k)))

    owasp = issue.get("owasp")
    if isinstance(owasp, dict):
        candidates.extend(_as_list(owasp.get("2021")))
        candidates.extend(_as_list(owasp.get("owasp_top_10_2021")))
        candidates.extend(_as_list(owasp.get("top_10_2021")))

    flattened: List[str] = []
    for v in candidates:
        if v is None:
            continue
        if isinstance(v, dict):
            codes = v.get("codes") or v.get("code") or v.get("owasp")
            for c in _as_list(codes):
                if c is not None:
                    flattened.append(str(c))
        else:
            flattened.append(str(v))

    return [s for s in flattened if s.strip()]


def _extract_cwe_candidates(issue: Dict[str, Any]) -> List[Any]:
    cands: List[Any] = []
    for k in (
        "cwe",
        "cwe_id",
        "cwe_ids",
        "cwe_classes",
        "cweClasses",
        "cweIds",
        "cweId",
        "cweID",
    ):
        cands.extend(_as_list(issue.get(k)))

    weakness = issue.get("weakness") or issue.get("weaknesses")
    if isinstance(weakness, dict):
        cands.extend(_as_list(weakness.get("cwe")))
        cands.extend(_as_list(weakness.get("cwe_id")))
        cands.extend(_as_list(weakness.get("cwe_ids")))
    elif isinstance(weakness, list):
        for w in weakness:
            if isinstance(w, dict):
                cands.extend(_as_list(w.get("cwe")))
                cands.extend(_as_list(w.get("cwe_id")))
                cands.extend(_as_list(w.get("cwe_ids")))

    return cands


def _collect_tags(issue: Dict[str, Any]) -> List[str]:
    tags: List[str] = []
    for k in ("tags", "labels", "categories", "category", "type", "subtype", "language", "rule", "rule_id"):
        for v in _as_list(issue.get(k)):
            if v is None or isinstance(v, (dict, list)):
                continue
            s = str(v).strip()
            if s:
                tags.append(s)

    for k in ("title", "summary", "message", "description"):
        v = issue.get(k)
        if isinstance(v, str) and v.strip():
            tags.append(v.strip())

    for v in _as_list(issue.get("owasp")):
        if isinstance(v, str) and v.strip():
            tags.append(v.strip())

    return tags


def _build_finding(*, issue: Dict[str, Any], per_finding_metadata: Dict[str, Any], cwe_to_owasp_map: Dict[str, Any]) -> Dict[str, Any]:
    issue_id = issue.get("id")
    rule_id = _extract_rule_id(issue)
    title = _extract_title(issue, issue_id)
    severity = _map_severity(issue)
    file_path, line, end_line = _extract_location(issue)

    tags = _collect_tags(issue)
    cwe_candidates = _extract_cwe_candidates(issue)
    vendor_owasp_2021 = _extract_vendor_owasp_2021_codes(issue)

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

    issues_raw = json.loads(raw_results_path.read_text(encoding="utf-8"))

    if isinstance(issues_raw, list):
        issues: List[Dict[str, Any]] = [x for x in issues_raw if isinstance(x, dict)]
    elif isinstance(issues_raw, dict) and isinstance(issues_raw.get("data"), list):
        issues = [x for x in issues_raw["data"] if isinstance(x, dict)]
    else:
        issues = []

    cwe_to_owasp_map = load_cwe_to_owasp_map()
    findings: List[Dict[str, Any]] = []

    for issue in issues:
        try:
            findings.append(_build_finding(issue=issue, per_finding_metadata=per_finding_metadata, cwe_to_owasp_map=cwe_to_owasp_map))
        except Exception as e:
            findings.append(
                {
                    "metadata": per_finding_metadata,
                    "finding_id": f"aikido:parse_error:{issue.get('id')}",
                    "rule_id": _extract_rule_id(issue),
                    "title": _extract_title(issue, issue.get("id")) or "Aikido issue (parse_error)",
                    "severity": _map_severity(issue),
                    "file_path": (
                        issue.get("file_path")
                        or issue.get("file")
                        or issue.get("path")
                        or issue.get("affected_file")
                        or issue.get("affectedFile")
                    ),
                    "line_number": _coerce_int(issue.get("line") or issue.get("line_number")),
                    "end_line_number": _coerce_int(issue.get("end_line") or issue.get("end_line_number")),
                    "line_content": None,
                    "cwe_id": None,
                    "cwe_ids": [],
                    "owasp_top_10_2017": None,
                    "owasp_top_10_2021": None,
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
