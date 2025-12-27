"""
tools/classification_resolver.py

Centralized OWASP/CWE resolution logic used by scanner normalizers.

Important distinction:
- The mappings folder centralizes the *data* (offline tables).
- This module centralizes the *policy* for how to apply that data consistently.

This is intentionally tool-agnostic:
- Snyk can pass vendor_owasp_2021_codes from an offline rule-doc mapping.
- Semgrep/Aikido can pass vendor_owasp_2021_codes=[] and rely on tags + CWE mapping.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set


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
    "A10": "Server-Side Request Forgery (SSRF)",
}


_CWE_NUM_RE = re.compile(r"(?i)\bCWE[-_ ]?(\d{1,6})\b")
_OWASP_CODE_RE = re.compile(r"(?i)\bA0?(\d{1,2})\b")


def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _flatten(values: Iterable[Any]) -> Iterable[Any]:
    """Flatten nested lists/tuples/sets while treating strings as scalars."""
    for v in values:
        if v is None:
            continue
        if isinstance(v, (list, tuple, set)):
            yield from _flatten(v)
        else:
            yield v


def _normalize_cwe(value: Any) -> Optional[str]:
    if value is None:
        return None
    # bool is a subclass of int in Python, but should never be treated as a CWE id.
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f"CWE-{value}" if value > 0 else None
    if not isinstance(value, str):
        return None

    s = value.strip()
    if not s:
        return None

    m = _CWE_NUM_RE.search(s)
    if m:
        n = int(m.group(1))
        return f"CWE-{n}" if n > 0 else None

    # handle "cwe:79" or "79"
    s2 = s.lower().replace("cwe:", "").replace("cwe", "").replace("-", "").replace("_", "").strip()
    if s2.isdigit():
        n = int(s2)
        return f"CWE-{n}" if n > 0 else None

    return None


def _normalize_owasp_code(raw: Any, year: str) -> Optional[str]:
    n: Optional[int] = None
    if raw is None:
        return None
    # bool is a subclass of int; treat it as invalid.
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        n = raw
    elif isinstance(raw, str):
        m = _OWASP_CODE_RE.search(raw.strip())
        if m:
            n = int(m.group(1))
    if n is None or n < 1 or n > 10:
        return None

    if year == "2017":
        return f"A{n}"
    if year == "2021":
        return f"A{n:02d}"
    raise ValueError(f"Unsupported OWASP year: {year}")


def _build_owasp_block(codes: Sequence[str], year: str) -> Optional[Dict[str, Any]]:
    if not codes:
        return None
    norm_codes = []
    for c in codes:
        nc = _normalize_owasp_code(c, year)
        if nc:
            norm_codes.append(nc)
    norm_codes = _dedupe_preserve_order(norm_codes)
    if not norm_codes:
        return None

    name_map = OWASP_TOP_10_2017_NAMES if year == "2017" else OWASP_TOP_10_2021_NAMES
    categories = []
    for c in norm_codes:
        name = name_map.get(c, "Unknown")
        categories.append(f"{c}:{year}-{name}")
    return {"codes": norm_codes, "categories": categories}


def _extract_owasp_codes_from_tags(tags: Sequence[str], year: str) -> List[str]:
    """
    Policy:
    - 2017: only accept tags that explicitly mention 2017.
    - 2021: accept explicit 2021 tags OR generic OWASP/top10 tags, excluding explicit 2017.
    """
    if not tags:
        return []
    codes: List[str] = []
    for t in tags:
        if not t:
            continue
        s = str(t).strip()
        if not s:
            continue
        low = s.lower()

        mentions_2017 = "2017" in low
        mentions_2021 = "2021" in low
        is_owaspish = ("owasp" in low) or ("top10" in low) or ("top 10" in low) or ("owasptop10" in low)

        if year == "2017":
            if not mentions_2017:
                continue
        elif year == "2021":
            if mentions_2017 and not mentions_2021:
                continue
            if not (mentions_2021 or is_owaspish):
                continue
        else:
            raise ValueError(f"Unsupported OWASP year: {year}")

        for g in _OWASP_CODE_RE.findall(s):
            try:
                n = int(g)
            except Exception:
                continue
            if 1 <= n <= 10:
                codes.append(f"A{n}")

    normed = []
    for c in codes:
        nc = _normalize_owasp_code(c, year)
        if nc:
            normed.append(nc)
    return _dedupe_preserve_order(normed)


def _unwrap_cwe_to_owasp_map(cwe_to_owasp_map: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accept either:
      - {"_meta":..., "cwe_to_owasp": {...}}
      - {"cwe_to_owasp": {...}}
      - {...} (already mapping)
    """
    if not isinstance(cwe_to_owasp_map, dict):
        return {}
    inner = cwe_to_owasp_map.get("cwe_to_owasp")
    if isinstance(inner, dict):
        return inner
    return cwe_to_owasp_map


def _derive_owasp_from_cwe_ids(
    cwe_ids: Sequence[str],
    cwe_to_owasp_map: Dict[str, Any],
) -> tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    mapping = _unwrap_cwe_to_owasp_map(cwe_to_owasp_map)
    if not mapping or not cwe_ids:
        return None, None

    o17: List[str] = []
    o21: List[str] = []

    def _extend_codes(dst: List[str], raw: Any) -> None:
        """Accept list/dict/string and append candidate OWASP codes to dst."""
        if raw is None:
            return
        if isinstance(raw, str):
            if raw.strip():
                dst.append(raw.strip())
            return
        if isinstance(raw, dict):
            codes = raw.get("codes")
            if isinstance(codes, (list, tuple, set)):
                for x in codes:
                    if x is None:
                        continue
                    s = str(x).strip()
                    if s:
                        dst.append(s)
            return
        if isinstance(raw, (list, tuple, set)):
            for x in raw:
                _extend_codes(dst, x)
            return

    for cwe in cwe_ids:
        entry = mapping.get(cwe)
        if not isinstance(entry, dict):
            # Some maps might key by numeric CWE string or int.
            m = _CWE_NUM_RE.search(cwe)
            if m:
                entry = mapping.get(m.group(1))
                if not isinstance(entry, dict):
                    try:
                        entry = mapping.get(int(m.group(1)))
                    except Exception:
                        entry = None
        if not isinstance(entry, dict):
            continue

        v17 = entry.get("owasp_top_10_2017") or entry.get("owasp_2017") or entry.get("owasp2017")
        v21 = entry.get("owasp_top_10_2021") or entry.get("owasp_2021") or entry.get("owasp2021")

        _extend_codes(o17, v17)
        _extend_codes(o21, v21)
    o17n = _dedupe_preserve_order([c for c in (_normalize_owasp_code(x, "2017") for x in o17) if c])
    o21n = _dedupe_preserve_order([c for c in (_normalize_owasp_code(x, "2021") for x in o21) if c])

    return _build_owasp_block(o17n, "2017"), _build_owasp_block(o21n, "2021")


def resolve_owasp_and_cwe(
    *,
    tags: Sequence[str],
    cwe_candidates: Sequence[Any],
    cwe_to_owasp_map: Dict[str, Any],
    vendor_owasp_2021_codes: Optional[Sequence[Any]] = None,
    allow_2017_from_tags: bool = True,
) -> Dict[str, Any]:
    """
    Tool-agnostic resolver.

    Inputs:
      - tags: free-form labels/metadata strings (can include OWASP and CWE fragments)
      - cwe_candidates: values that might contain CWE ids (ints/strings/lists/etc)
      - vendor_owasp_2021_codes: optional "strong" OWASP-2021 codes from a vendor mapping table
      - cwe_to_owasp_map: MITRE-derived mapping to derive OWASP from CWE

    Policy:
      - OWASP 2021: tags -> vendor_owasp_2021_codes -> derived from CWE
      - OWASP 2017: derived from CWE (primary), optional explicit 2017 tags if enabled
    """
    # CWE normalize
    norm_cwe_ids: List[str] = []
    for v in _flatten(cwe_candidates or []):
        c = _normalize_cwe(v)
        if c:
            norm_cwe_ids.append(c)
    norm_cwe_ids = _dedupe_preserve_order(norm_cwe_ids)
    cwe_id = norm_cwe_ids[0] if norm_cwe_ids else None

    # derive from CWE first (used for 2017 always, and 2021 as fallback)
    derived_2017, derived_2021 = _derive_owasp_from_cwe_ids(norm_cwe_ids, cwe_to_owasp_map)

    # OWASP 2017
    owasp2017_block = derived_2017
    if allow_2017_from_tags and owasp2017_block is None:
        codes_2017 = _extract_owasp_codes_from_tags(tags or [], "2017")
        owasp2017_block = _build_owasp_block(codes_2017, "2017") if codes_2017 else None

    # OWASP 2021: tags first
    codes_2021_tags = _extract_owasp_codes_from_tags(tags or [], "2021")
    owasp2021_block = _build_owasp_block(codes_2021_tags, "2021") if codes_2021_tags else None

    # then vendor codes if nothing from tags
    if owasp2021_block is None and vendor_owasp_2021_codes:
        vnorm: List[str] = []
        for v in _flatten(vendor_owasp_2021_codes):
            nc = _normalize_owasp_code(v, "2021")
            if nc:
                vnorm.append(nc)
        vnorm = _dedupe_preserve_order(vnorm)
        if vnorm:
            owasp2021_block = _build_owasp_block(vnorm, "2021")

    # then derived from CWE
    if owasp2021_block is None:
        owasp2021_block = derived_2021

    return {
        "cwe_id": cwe_id,
        "cwe_ids": norm_cwe_ids,
        "owasp_top_10_2017": owasp2017_block,
        "owasp_top_10_2021": owasp2021_block,
    }


# -------------------------
# Public helpers (reused by other normalizers)
# -------------------------


def normalize_cwe_id(value: Any) -> Optional[str]:
    """Public wrapper: normalize inputs into 'CWE-<num>' or None."""
    return _normalize_cwe(value)


def normalize_owasp_top10_code(raw: Any, year: str) -> Optional[str]:
    """Public wrapper: normalize inputs into an OWASP Top10 code for the given year."""
    return _normalize_owasp_code(raw, year)
