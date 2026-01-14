from __future__ import annotations

"""pipeline.analysis.utils.owasp

Small helper to attach OWASP Top 10 category metadata to analysis outputs.

We infer OWASP IDs in a best-effort, dependency-free way:
1) Prefer a captured GT file that explicitly declares `owasp: Axx`:
     <case_dir>/gt/gt_catalog.(yaml|yml)
     <case_dir>/gt/suite_sets.(yaml|yml)
2) Fallback to parsing the case_id (e.g., owasp2021-a03-injection -> A03).

This keeps the analysis pipeline usable even when GT scoring is disabled.
"""

import re
from pathlib import Path
from typing import Optional, Tuple


OWASP_TOP10_2021_TITLES: dict[str, str] = {
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


_RE_CASE_ID = re.compile(r"owasp\d{4}-a(\d{2})", re.IGNORECASE)
_RE_OWASP = re.compile(r"\bA(\d{1,2})\b", re.IGNORECASE)


def _normalize_owasp_id(v: str) -> Optional[str]:
    v = str(v or "").strip().upper()
    if not v:
        return None
    m = re.match(r"^A(\d{1,2})$", v)
    if not m:
        return None
    n = int(m.group(1))
    if n < 1 or n > 10:
        return None
    return f"A{n:02d}"


def _try_read_owasp_from_text_file(p: Path) -> Optional[str]:
    """Parse a small YAML-ish file for a top-level line like: `owasp: A03`.

    We intentionally do not depend on PyYAML here.
    """
    try:
        if not p.exists() or not p.is_file():
            return None
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines()[:50]:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s.lower().startswith("owasp:"):
                val = s.split(":", 1)[1].strip().strip("'\"")
                return _normalize_owasp_id(val)
    except Exception:
        return None
    return None


def infer_owasp(
    case_id: Optional[str],
    *,
    out_dir: Optional[Path] = None,
    case_dir: Optional[Path] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Return (owasp_id, owasp_title) or (None, None)."""

    # Derive case_dir from out_dir (common v2 layout)
    if case_dir is None and out_dir is not None:
        try:
            od = Path(out_dir)
            if od.name == "analysis":
                case_dir = od.parent
        except Exception:
            case_dir = None

    # Prefer explicit declaration from captured GT files
    if case_dir is not None:
        gt_dir = Path(case_dir) / "gt"
        for rel in (
            gt_dir / "gt_catalog.yaml",
            gt_dir / "gt_catalog.yml",
            gt_dir / "suite_sets.yaml",
            gt_dir / "suite_sets.yml",
        ):
            owasp_id = _try_read_owasp_from_text_file(rel)
            if owasp_id:
                return owasp_id, OWASP_TOP10_2021_TITLES.get(owasp_id)

    # Fallback to parsing case_id
    cid = str(case_id or "")
    m = _RE_CASE_ID.search(cid)
    if m:
        owasp_id = _normalize_owasp_id(f"A{int(m.group(1)):02d}")
        if owasp_id:
            return owasp_id, OWASP_TOP10_2021_TITLES.get(owasp_id)

    # Last-ditch: any bare Axx token
    m2 = _RE_OWASP.search(cid)
    if m2:
        owasp_id = _normalize_owasp_id(f"A{int(m2.group(1)):02d}")
        if owasp_id:
            return owasp_id, OWASP_TOP10_2021_TITLES.get(owasp_id)

    return None, None


__all__ = [
    "OWASP_TOP10_2021_TITLES",
    "infer_owasp",
]

