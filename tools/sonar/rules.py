"""tools/sonar/rules.py

Pure parsing logic for SonarCloud rule metadata.

Input: JSON returned by /api/rules/show
Output: a classification dict used as optional enrichment in normalized findings.

This module intentionally has **no HTTP calls**.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


OWASP_TOP_10_2021_NAMES: Dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

OWASP_TOP_10_2017_NAMES: Dict[str, str] = {
    "A1": "Injection",
    "A2": "Broken Authentication",
    "A3": "Sensitive Data Exposure",
    "A4": "XML External Entities (XXE)",
    "A5": "Broken Access Control",
    "A6": "Security Misconfiguration",
    "A7": "Cross-Site Scripting (XSS)",
    "A8": "Insecure Deserialization",
    "A9": "Using Components with Known Vulnerabilities",
    "A10": "Insufficient Logging & Monitoring",
}


def build_owasp_block(
    codes: List[str],
    names_map: Dict[str, str],
    year_label: str,
) -> Optional[Dict[str, Any]]:
    codes = codes or []
    if not codes:
        return None

    categories: List[str] = []
    for code in codes:
        code_str = (code or "").strip()
        if not code_str:
            continue
        name = names_map.get(code_str, "Unknown")
        categories.append(f"{code_str}:{year_label}-{name}")

    if not categories:
        return None
    return {"codes": codes, "categories": categories}


def parse_rule_classification(*, rule_key: str, rules_show_json: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parse /api/rules/show response JSON into enrichment fields."""
    rule = (rules_show_json or {}).get("rule")
    if not isinstance(rule, dict):
        return None

    name = rule.get("name")
    tags = rule.get("tags") or []
    security_standards = rule.get("securityStandards") or []

    cwe_ids: List[str] = []
    owasp2017_codes: List[str] = []
    owasp2021_codes: List[str] = []

    # securityStandards can be dict or list
    if isinstance(security_standards, dict):
        for c in security_standards.get("CWE", []) or []:
            c_str = str(c).strip()
            if c_str:
                cwe_ids.append(f"CWE-{c_str}")
        owasp2017_codes = list(security_standards.get("OWASP Top 10 2017", []) or [])
        owasp2021_codes = list(security_standards.get("OWASP Top 10 2021", []) or [])

    elif isinstance(security_standards, list):
        for entry in security_standards:
            if not isinstance(entry, str):
                continue
            lower = entry.lower()

            if lower.startswith("cwe:"):
                num = entry.split(":", 1)[1].strip()
                if num:
                    cwe_ids.append(f"CWE-{num.upper()}")
                continue

            if "owasptop10-2021" in lower:
                code_part = entry.split(":", 1)[1].strip() if ":" in entry else ""
                if code_part:
                    code = code_part.upper()
                    if not code.startswith("A"):
                        code = "A" + code
                    owasp2021_codes.append(code)
                continue

            if "owasptop10-2017" in lower or "owasptop10:" in lower:
                code_part = entry.split(":", 1)[1].strip() if ":" in entry else ""
                if code_part:
                    code = code_part.upper()
                    if not code.startswith("A"):
                        code = "A" + code
                    owasp2017_codes.append(code)
                continue

    # fallback CWE from tags (e.g. cwe-89)
    for t in tags:
        if not isinstance(t, str):
            continue
        lower = t.lower()
        if lower.startswith("cwe-"):
            num = lower.split("cwe-", 1)[1]
            if num:
                cwe_ids.append(f"CWE-{num.upper()}")

    # dedupe while preserving order
    seen_cwe: set[str] = set()
    deduped: List[str] = []
    for cid in cwe_ids:
        if cid not in seen_cwe:
            seen_cwe.add(cid)
            deduped.append(cid)
    cwe_ids = deduped

    owasp2017_codes = list(dict.fromkeys(owasp2017_codes))
    owasp2021_codes = list(dict.fromkeys(owasp2021_codes))

    return {
        "rule_key": rule_key,
        "vuln_class": name,
        "cwe_ids": cwe_ids,
        "owasp_top_10_2017": build_owasp_block(owasp2017_codes, OWASP_TOP_10_2017_NAMES, "2017"),
        "owasp_top_10_2021": build_owasp_block(owasp2021_codes, OWASP_TOP_10_2021_NAMES, "2021"),
    }
