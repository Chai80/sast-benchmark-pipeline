"""tools/classification_resolver.py

Centralized OWASP/CWE resolution logic used by *all* scanner normalizers.

Why this file exists
--------------------
Different scanners expose different pieces of classification data:
  - Some provide explicit OWASP Top 10 labels ("vendor OWASP")
  - Some provide CWE IDs only
  - Some provide neither (or provide them inconsistently)

To make cross-tool benchmarking possible, we want a single place where:
  1) We normalize *formats* (e.g., OWASP 2021 uses canonical A01..A10 codes)
  2) We define *policy* (when do we trust vendor labels vs derived labels)
  3) We can compute two explicit views for fair comparisons:

     - Vendor OWASP: what the tool explicitly claims (tags / vendor mapping)
     - Canonical OWASP: derived uniformly from CWE via a shared mapping table

Important distinction
--------------------
The `mappings/` folder centralizes the *data* (offline tables).
This module centralizes the *policy* for how to apply that data consistently.

Tool-agnostic inputs
-------------------
  - Snyk can pass `vendor_owasp_2021_codes` from an offline rule-doc mapping.
  - Semgrep/Aikido can pass `vendor_owasp_2021_codes=None` and rely on tags + CWE mapping.
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

    Outputs
    -------
    This function returns *both* vendor and canonical OWASP views.

      - `owasp_top_10_2021_vendor`: Derived ONLY from tool-provided labels (tags / vendor mapping).
      - `owasp_top_10_2021_canonical`: Derived ONLY from CWE via the shared MITRE mapping.

    For backwards compatibility, we also keep the existing fields:
      - `owasp_top_10_2021`: a "resolved" view (vendor preferred; fallback to canonical)
      - `owasp_top_10_2017`: a "resolved" view (canonical preferred; fallback to vendor tags)

    Why both views?
      - Vendor labels are useful for "what the tool says".
      - Canonical labels allow apples-to-apples comparisons across scanners.
    """
    # CWE normalize
    norm_cwe_ids: List[str] = []
    for v in _flatten(cwe_candidates or []):
        c = _normalize_cwe(v)
        if c:
            norm_cwe_ids.append(c)
    norm_cwe_ids = _dedupe_preserve_order(norm_cwe_ids)
    cwe_id = norm_cwe_ids[0] if norm_cwe_ids else None

    # Derive from CWE first.
    # This is our *canonical* view because it's tool-agnostic.
    derived_2017, derived_2021 = _derive_owasp_from_cwe_ids(norm_cwe_ids, cwe_to_owasp_map)

    # ----------------------------
    # OWASP Top 10 2017
    # ----------------------------
    # Canonical 2017 = derived from CWE.
    owasp2017_canonical = derived_2017

    # Vendor 2017 = explicit 2017 tags (opt-in).
    owasp2017_vendor: Optional[Dict[str, Any]] = None
    if allow_2017_from_tags:
        codes_2017 = _extract_owasp_codes_from_tags(tags or [], "2017")
        owasp2017_vendor = _build_owasp_block(codes_2017, "2017") if codes_2017 else None

    # Backwards compatible "resolved" view:
    # historically we preferred CWE-derived 2017 (if available), otherwise tags.
    owasp2017_resolved = owasp2017_canonical or owasp2017_vendor

    # ----------------------------
    # OWASP Top 10 2021
    # ----------------------------
    # Canonical 2021 = derived from CWE.
    owasp2021_canonical = derived_2021

    # Vendor 2021 = tool-provided labels.
    # IMPORTANT: Vendor view should NOT fall back to CWE derivation.
    # (Otherwise it becomes a blended view and is not comparable across tools.)
    codes_2021_tags = _extract_owasp_codes_from_tags(tags or [], "2021")
    owasp2021_vendor = _build_owasp_block(codes_2021_tags, "2021") if codes_2021_tags else None

    # If no 2021 tags, use explicit vendor mapping codes (e.g., Snyk offline table).
    if owasp2021_vendor is None and vendor_owasp_2021_codes:
        vnorm: List[str] = []
        for v in _flatten(vendor_owasp_2021_codes):
            nc = _normalize_owasp_code(v, "2021")
            if nc:
                vnorm.append(nc)
        vnorm = _dedupe_preserve_order(vnorm)
        if vnorm:
            owasp2021_vendor = _build_owasp_block(vnorm, "2021")

    # Backwards compatible "resolved" view:
    # historically we preferred tool-provided 2021 (tags/vendor), otherwise CWE-derived.
    owasp2021_resolved = owasp2021_vendor or owasp2021_canonical

    return {
        "cwe_id": cwe_id,
        "cwe_ids": norm_cwe_ids,

        # Backwards-compatible fields (existing schema keys)
        "owasp_top_10_2017": owasp2017_resolved,
        "owasp_top_10_2021": owasp2021_resolved,

        # New explicit views (for fair benchmarking)
        "owasp_top_10_2017_vendor": owasp2017_vendor,
        "owasp_top_10_2017_canonical": owasp2017_canonical,
        "owasp_top_10_2021_vendor": owasp2021_vendor,
        "owasp_top_10_2021_canonical": owasp2021_canonical,
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
