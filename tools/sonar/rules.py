"""tools.sonar.rules

Pure parsing + normalization logic for SonarCloud rule metadata.

- `api.py` is responsible for HTTP calls.
- This module is responsible for turning Sonar rule metadata into the
  *pipeline's* normalized classification fields (CWE + OWASP Top 10).

Why this exists:
SonarCloud's `/api/issues/search` gives you *issues*, but OWASP/CWE
classifications typically live on the *rule* (`/api/rules/show`).
We enrich issues by fetching rule details, then parsing them here.

Notes:
- SonarCloud may emit OWASP 2021 identifiers as `A1`..`A10` (no leading zero).
  The pipeline uses canonical 2021 codes `A01`..`A10`.
- We rely on `tools.classification_resolver` for the canonical OWASP code
  normalization + name tables so all scanners stay consistent.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from tools.classification_resolver import (
    OWASP_TOP_10_2017_NAMES,
    OWASP_TOP_10_2021_NAMES,
    normalize_owasp_top10_code,
)


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    """Remove duplicates while preserving order."""
    seen: set[str] = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def build_owasp_block(raw_codes: List[str], year: str) -> Optional[Dict[str, Any]]:
    """Build the normalized OWASP block.

    Returns:
        {"codes": [...], "categories": [...]} or None

    `codes` are canonical:
      - 2017: A1..A10
      - 2021: A01..A10

    `categories` are human-readable strings like:
      - A1:2017-Injection
      - A03:2021-Injection
    """
    if not raw_codes:
        return None

    # Normalize to canonical codes first.
    norm_codes: List[str] = []
    for c in raw_codes:
        norm = normalize_owasp_top10_code(c, year)
        if norm:
            norm_codes.append(norm)

    norm_codes = _dedupe_preserve_order(norm_codes)
    if not norm_codes:
        return None

    name_map = OWASP_TOP_10_2017_NAMES if year == "2017" else OWASP_TOP_10_2021_NAMES

    categories: List[str] = []
    for code in norm_codes:
        name = name_map.get(code, "Unknown")
        categories.append(f"{code}:{year}-{name}")

    return {"codes": norm_codes, "categories": categories}


def parse_rule_classification(*, rule_key: str, rules_show_json: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parse `/api/rules/show` JSON into a normalized classification dict.

    SonarCloud returns classifications under `rule.securityStandards`.
    Depending on API version/endpoint, it can be either:
      - a dict: {"CWE": [...], "OWASP Top 10 2021": [...], ...}
      - a list: ["cwe:89", "owaspTop10-2021:a3", ...]

    We also parse CWE IDs from tags like `cwe-89`.
    """
    rule = (rules_show_json or {}).get("rule")
    if not isinstance(rule, dict):
        return None

    name = rule.get("name")
    tags = rule.get("tags") or []
    security_standards = rule.get("securityStandards") or []

    cwe_ids: List[str] = []
    owasp2017_codes: List[str] = []
    owasp2021_codes: List[str] = []

    # -------------------------
    # securityStandards
    # -------------------------
    if isinstance(security_standards, dict):
        # CWE as "79" or "CWE-79" or "cwe-79" etc.
        for cwe in security_standards.get("CWE", []) or []:
            s = str(cwe).strip()
            if not s:
                continue
            s_upper = s.upper()
            if not s_upper.startswith("CWE-"):
                s_upper = f"CWE-{s_upper.lstrip('CWE-')}"
            cwe_ids.append(s_upper)

        # Sonar might return "A1"/"A3" etc. We'll canonicalize in build_owasp_block.
        owasp2017_codes.extend([str(x).strip() for x in (security_standards.get("OWASP Top 10 2017", []) or []) if str(x).strip()])
        owasp2021_codes.extend([str(x).strip() for x in (security_standards.get("OWASP Top 10 2021", []) or []) if str(x).strip()])

    elif isinstance(security_standards, list):
        for entry in security_standards:
            if not isinstance(entry, str):
                continue
            s = entry.strip()
            low = s.lower()

            if low.startswith("cwe:"):
                cwe = s.split(":", 1)[1].strip()
                if cwe:
                    cwe_ids.append(f"CWE-{cwe}" if not cwe.upper().startswith("CWE-") else cwe.upper())
                continue

            # OWASP Top 10 standards
            if "owasptop10-2021" in low:
                code_part = s.split(":", 1)[1].strip() if ":" in s else s
                if code_part:
                    owasp2021_codes.append(code_part)
                continue

            if "owasptop10-2017" in low:
                code_part = s.split(":", 1)[1].strip() if ":" in s else s
                if code_part:
                    owasp2017_codes.append(code_part)
                continue

            # Some Sonar installations may return an unversioned `owaspTop10:`
            # Historically that maps to the 2017 Top 10.
            if low.startswith("owasptop10:") or "owasptop10:" in low:
                code_part = s.split(":", 1)[1].strip() if ":" in s else s
                if code_part:
                    owasp2017_codes.append(code_part)

    # -------------------------
    # tags (fallback CWE)
    # -------------------------
    if isinstance(tags, list):
        for t in tags:
            if not isinstance(t, str):
                continue
            tl = t.strip().lower()
            if tl.startswith("cwe-"):
                num = tl.split("-", 1)[1].strip()
                if num.isdigit():
                    cwe_ids.append(f"CWE-{num}")

    cwe_ids = _dedupe_preserve_order([c.upper() for c in cwe_ids if c])

    owasp_top_10_2017 = build_owasp_block(owasp2017_codes, "2017")
    owasp_top_10_2021 = build_owasp_block(owasp2021_codes, "2021")

    return {
        "rule_key": rule_key,
        "vuln_class": name,
        "cwe_ids": cwe_ids,
        "owasp_top_10_2017": owasp_top_10_2017,
        "owasp_top_10_2021": owasp_top_10_2021,
    }
