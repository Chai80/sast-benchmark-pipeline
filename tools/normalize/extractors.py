"""tools/normalize/extractors.py

Shared, boring, reusable extraction helpers for scanner normalizers.

Why this exists
--------------
Each scanner (Snyk, Aikido, Semgrep, Sonar, ...) tends to have its own JSON
shape for:
  - file/line locations
  - CWE ids (sometimes nested, sometimes strings, sometimes ints)
  - OWASP Top 10 tags/codes
  - severity vocabularies

When every scan_*.py re-implements these small pieces, the project slowly
accumulates copy/paste drift ("spaghetti" in the *architecture* sense). This
module centralizes extraction/normalization so each scan script can be a thin
orchestrator.

Design constraints
------------------
* Pure functions only (no IO, no subprocess).
* Conservative best-effort parsing.
* Keep public function names stable so scan scripts don't churn.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Dict, List, Optional, Sequence

from .classification import normalize_cwe_id, normalize_owasp_top10_code


# NOTE: These regexes are for *finding candidates* in text. Canonical
# canonical normalization lives in normalize_cwe_id / normalize_owasp_top10_code.
_CWE_RE = re.compile(r"(?i)\bCWE[-_ ]?(\d{1,6})\b")
_OWASP_2021_RE = re.compile(r"(?i)\bA0?(10|[1-9])\b")  # matches A1/A01..A10


@dataclass(frozen=True)
class NormalizedLocation:
    file_path: Optional[str]
    line_number: Optional[int]
    end_line_number: Optional[int]


def _as_list(v: Any) -> List[Any]:
    """Coerce scalars to a list and normalize None to []."""
    if v is None:
        return []
    if isinstance(v, list):
        return v
    if isinstance(v, tuple):
        return list(v)
    if isinstance(v, set):
        return list(v)
    return [v]


def _dedupe_preserve_order(items: Sequence[str]) -> List[str]:
    """De-dupe items while preserving first-seen order."""
    seen: set[str] = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _coerce_int(v: Any) -> Optional[int]:
    """Best-effort int coercion (guards against bool-as-int)."""
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    try:
        return int(str(v).strip())
    except (ValueError, TypeError):
        return None


def _get(d: Any, *keys: str) -> Any:
    """Safely walk nested dict keys given an explicit key path."""
    cur = d
    for k in keys:
        if cur is None or not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


# ---------------------------------------------------------------------------
# Public helpers: token normalization
# ---------------------------------------------------------------------------


def normalize_cwe_token(token: Any) -> Optional[str]:
    """Normalize common CWE token shapes into 'CWE-<num>' (or None)."""
    return normalize_cwe_id(token)


def normalize_owasp_2021_code(token: Any) -> Optional[str]:
    """Normalize OWASP Top 10:2021 code shapes into 'A01'..'A10' (or None)."""
    return normalize_owasp_top10_code(token, "2021")


# ---------------------------------------------------------------------------
# Public helpers: generic text/tag collection
# ---------------------------------------------------------------------------


def collect_text_blobs(*items: Any) -> List[str]:
    """Collect de-duped, non-empty strings from nested structures."""
    out: List[str] = []

    def _walk(x: Any) -> None:
        if x is None:
            return
        if isinstance(x, str):
            s = x.strip()
            if s:
                out.append(s)
            return
        if isinstance(x, (int, float, bool)):
            return
        if isinstance(x, dict):
            for v in x.values():
                _walk(v)
            return
        if isinstance(x, (list, tuple, set)):
            for v in x:
                _walk(v)
            return

    for it in items:
        _walk(it)

    return _dedupe_preserve_order(out)


def collect_tags_and_text(
    obj: Dict[str, Any],
    *,
    tool: Optional[str] = None,
    extra_text: Sequence[str] = (),
) -> List[str]:
    """Extract tag-ish signals + high-signal text fields for classification."""
    tags: List[str] = []

    # Common tag containers
    for key in ("tags", "labels", "categories", "category"):
        v = obj.get(key) if isinstance(obj, dict) else None
        for t in _as_list(v):
            if isinstance(t, str) and t.strip():
                tags.append(t.strip())

    # Tool-specific helpful fields
    if tool == "aikido":
        for key in (
            "type",
            "subtype",
            "language",
            "rule_id",
            "rule",
            "attack_surface",
            "programming_language",
            "cve_id",
            "affected_package",
        ):
            v = obj.get(key)
            if isinstance(v, str) and v.strip():
                tags.append(v.strip())

    elif tool == "semgrep":
        for key in ("check_id", "message"):
            v = obj.get(key)
            if isinstance(v, str) and v.strip():
                tags.append(v.strip())

        meta = obj.get("extra") or obj.get("metadata") or {}
        if isinstance(meta, dict):
            for key in ("category", "subcategory", "technology", "confidence"):
                v = meta.get(key)
                for t in _as_list(v):
                    if isinstance(t, str) and t.strip():
                        tags.append(t.strip())

    elif tool == "snyk":
        # SARIF results/rules often have names/ids/tags extracted elsewhere.
        for key in ("ruleId", "rule_id", "name", "shortDescription", "help", "message"):
            v = obj.get(key)
            if isinstance(v, str) and v.strip():
                tags.append(v.strip())

    # High-signal descriptive text fields
    for key in ("title", "summary", "description", "message"):
        v = obj.get(key)
        if isinstance(v, str) and v.strip():
            tags.append(v.strip())

    tags.extend([t.strip() for t in extra_text if isinstance(t, str) and t.strip()])

    return _dedupe_preserve_order(tags)


# ---------------------------------------------------------------------------
# Public helpers: CWE / OWASP extraction from tool payloads
# ---------------------------------------------------------------------------


def extract_cwe_candidates(obj: Dict[str, Any]) -> List[str]:
    """Extract CWE candidates from common vendor payload shapes."""
    candidates: List[str] = []

    # Most common direct keys
    direct_keys = (
        "cwe",
        "cwe_id",
        "cwe_ids",
        "cweIds",
        "cwe_classes",
        "cweClasses",
        "cwe_class",
        "cweClass",
    )
    for key in direct_keys:
        for v in _as_list(obj.get(key) if isinstance(obj, dict) else None):
            norm = normalize_cwe_token(v)
            if norm:
                candidates.append(norm)

    # Nested weaknesses
    weaknesses = obj.get("weaknesses") or obj.get("weakness") or None
    for w in _as_list(weaknesses):
        if isinstance(w, dict):
            for k in ("cwe", "cwe_id", "cweId", "id", "name"):
                norm = normalize_cwe_token(w.get(k))
                if norm:
                    candidates.append(norm)
        else:
            norm = normalize_cwe_token(w)
            if norm:
                candidates.append(norm)

    # Regex scan in descriptive text fields (helps when tools embed "CWE-79" in descriptions).
    blobs = collect_text_blobs(
        obj.get("title"),
        obj.get("summary"),
        obj.get("description"),
        obj.get("message"),
        obj.get("rule"),
        obj.get("help"),
    )
    for b in blobs:
        for m in _CWE_RE.finditer(b):
            norm = normalize_cwe_token(m.group(0))
            if norm:
                candidates.append(norm)

    return _dedupe_preserve_order(candidates)


def extract_vendor_owasp_2021_codes(obj: Dict[str, Any]) -> List[str]:
    """Extract explicit vendor-provided OWASP Top 10:2021 codes from payloads."""
    codes: List[str] = []

    def _collect(val: Any) -> None:
        """Collect codes from mixed payload shapes (scalars/lists/dicts)."""
        if val is None:
            return

        # Dicts may wrap codes under a known key.
        if isinstance(val, dict):
            for kk in ("codes", "code", "id", "name", "category", "owasp"):
                _collect(val.get(kk))
            return

        for v in _as_list(val):
            if isinstance(v, dict):
                for kk in ("codes", "code", "id", "name", "category", "owasp"):
                    _collect(v.get(kk))
            else:
                c = normalize_owasp_2021_code(v)
                if c:
                    codes.append(c)

    # Direct keys used by some mapping JSON or exports.
    for key in ("owasp_top_10_2021", "owasp_2021", "owaspTop10_2021", "owaspTop10"):
        _collect(obj.get(key) if isinstance(obj, dict) else None)

    # Nested under an "owasp" object (seen in some exports).
    # Example shapes:
    #   {"owasp": {"2021": ["A03", ...]}}
    #   {"owasp": {"owasp_top_10_2021": {"codes": ["A01", ...]}}}
    owasp = obj.get("owasp") if isinstance(obj, dict) else None
    if isinstance(owasp, dict):
        for key in ("2021", "owasp_top_10_2021", "top_10_2021"):
            _collect(owasp.get(key))

    # regex scan in text blobs
    blobs = collect_text_blobs(
        obj.get("title"),
        obj.get("summary"),
        obj.get("description"),
        obj.get("message"),
        obj.get("rule"),
    )
    for b in blobs:
        for m in _OWASP_2021_RE.finditer(b):
            c = normalize_owasp_2021_code(m.group(0))
            if c:
                codes.append(c)

    return _dedupe_preserve_order(codes)


# ---------------------------------------------------------------------------
# Public helpers: severity and locations
# ---------------------------------------------------------------------------


def map_severity(raw: Any, *, tool: Optional[str] = None) -> Optional[str]:
    """Map vendor severity into the normalized set (HIGH/MEDIUM/LOW).

    Returns None if we can't determine a severity.
    """
    if raw is None:
        return None

    s = str(raw).strip().lower()
    if not s:
        return None

    # Some tools have numeric severity_score; allow that.
    if s.replace(".", "", 1).isdigit():
        try:
            score = float(s)
        except ValueError:
            score = None
        if score is None:
            return None
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return None

    if s in {"critical", "crit", "blocker", "major", "high", "error"}:
        return "HIGH"
    if s in {"medium", "moderate", "warning", "warn", "minor"}:
        return "MEDIUM"
    if s in {"low", "info", "informational", "note", "none"}:
        return "LOW"

    # Tool-specific oddities
    if tool == "aikido":
        if "critical" in s or "high" in s:
            return "HIGH"
        if "medium" in s:
            return "MEDIUM"
        if "low" in s or "info" in s:
            return "LOW"

    return None


def extract_location(obj: Dict[str, Any], *, tool: str) -> NormalizedLocation:
    """Extract file/line from vendor payloads for a specific tool."""
    if not isinstance(obj, dict):
        return NormalizedLocation(file_path=None, line_number=None, end_line_number=None)

    if tool == "aikido":
        file_path = (
            obj.get("file_path")
            or obj.get("file")
            or obj.get("path")
            or obj.get("affected_file")
            or obj.get("affectedFile")
            or obj.get("filePath")
        )
        line = _coerce_int(
            obj.get("start_line")
            or obj.get("startLine")
            or obj.get("line")
            or obj.get("line_number")
        )
        end_line = _coerce_int(
            obj.get("end_line") or obj.get("endLine") or obj.get("end_line_number")
        )

        # Some exports nest location under a "location" or "source_location" object.
        loc = obj.get("location") or obj.get("source_location") or obj.get("sourceLocation")
        if isinstance(loc, dict):
            file_path = (
                file_path
                or loc.get("file_path")
                or loc.get("file")
                or loc.get("path")
                or loc.get("affected_file")
                or loc.get("affectedFile")
                or loc.get("filePath")
            )
            line = line or _coerce_int(
                loc.get("start_line")
                or loc.get("startLine")
                or loc.get("line")
                or loc.get("line_number")
            )
            end_line = end_line or _coerce_int(
                loc.get("end_line") or loc.get("endLine") or loc.get("end_line_number")
            )

        return NormalizedLocation(
            file_path=str(file_path) if file_path else None,
            line_number=line,
            end_line_number=end_line,
        )

    if tool == "semgrep":
        file_path = obj.get("path") or _get(obj, "location", "path")
        start_line = _coerce_int(
            _get(obj, "start", "line") or obj.get("start_line") or obj.get("line")
        )
        end_line = _coerce_int(
            _get(obj, "end", "line") or obj.get("end_line") or obj.get("endLine")
        )
        return NormalizedLocation(
            file_path=str(file_path) if file_path else None,
            line_number=start_line,
            end_line_number=end_line,
        )

    if tool == "sarif":
        # expects a SARIF result dict with locations[0].physicalLocation...
        loc0 = None
        locs = obj.get("locations")
        if isinstance(locs, list) and locs:
            loc0 = locs[0]

        phys = (loc0 or {}).get("physicalLocation") if isinstance(loc0, dict) else None
        artifact = (phys or {}).get("artifactLocation") if isinstance(phys, dict) else None
        region = (phys or {}).get("region") if isinstance(phys, dict) else None

        file_path = None
        if isinstance(artifact, dict):
            file_path = artifact.get("uri")

        start_line = _coerce_int(region.get("startLine") if isinstance(region, dict) else None)
        end_line = _coerce_int(region.get("endLine") if isinstance(region, dict) else None)
        return NormalizedLocation(
            file_path=str(file_path) if file_path else None,
            line_number=start_line,
            end_line_number=end_line,
        )

    # fallback generic
    file_path = obj.get("file_path") or obj.get("file") or obj.get("path")
    line = _coerce_int(obj.get("line_number") or obj.get("line") or obj.get("start_line"))
    end_line = _coerce_int(obj.get("end_line_number") or obj.get("end_line") or obj.get("endLine"))
    return NormalizedLocation(
        file_path=str(file_path) if file_path else None,
        line_number=line,
        end_line_number=end_line,
    )
