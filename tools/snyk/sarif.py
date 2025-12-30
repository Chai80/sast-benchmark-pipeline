"""tools/snyk/sarif.py

Minimal SARIF helpers for Snyk normalization.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tools.core import normalize_repo_relative_path, read_line_content

_CWE_RE = re.compile(r"(CWE-\d+)", re.IGNORECASE)


def severity_from_level(level: Optional[str]) -> Optional[str]:
    if not level:
        return None
    lvl = str(level).strip().lower()
    if lvl == "error":
        return "HIGH"
    if lvl == "warning":
        return "MEDIUM"
    if lvl in ("note", "none"):
        return "LOW"
    return "MEDIUM"


def rules_by_id(run_obj: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rules = (((run_obj.get("tool") or {}).get("driver") or {}).get("rules")) or []
    out: Dict[str, Dict[str, Any]] = {}
    if isinstance(rules, list):
        for r in rules:
            if isinstance(r, dict) and isinstance(r.get("id"), str):
                out[r["id"]] = r
    return out


def rule_name(rule_def: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(rule_def, dict):
        return None
    if isinstance(rule_def.get("name"), str) and rule_def["name"].strip():
        return rule_def["name"].strip()
    sd = rule_def.get("shortDescription")
    if isinstance(sd, dict) and isinstance(sd.get("text"), str):
        return sd["text"].strip()
    return None


def collect_text_blobs(rule_def: Optional[Dict[str, Any]]) -> List[str]:
    if not isinstance(rule_def, dict):
        return []
    blobs: List[str] = []
    for path in (("help", "text"), ("fullDescription", "text"), ("shortDescription", "text"), ("name",)):
        cur: Any = rule_def
        for k in path:
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(k)
        if isinstance(cur, str) and cur.strip():
            blobs.append(cur.strip())
    return blobs


def extract_tags(rule_def: Optional[Dict[str, Any]], res: Dict[str, Any]) -> List[str]:
    tags: List[str] = []

    rp = (rule_def or {}).get("properties") if isinstance(rule_def, dict) else None
    if isinstance(rp, dict):
        if isinstance(rp.get("tags"), list):
            tags += [str(x) for x in (rp.get("tags") or [])]

    sp = res.get("properties")
    if isinstance(sp, dict) and isinstance(sp.get("tags"), list):
        tags += [str(x) for x in (sp.get("tags") or [])]

    tags += collect_text_blobs(rule_def)

    seen = set()
    out: List[str] = []
    for t in tags:
        tt = str(t).strip()
        if tt and tt not in seen:
            seen.add(tt)
            out.append(tt)
    return out


def extract_cwe_candidates(res: Dict[str, Any], rule_def: Optional[Dict[str, Any]], tags: List[str]) -> List[str]:
    cands: List[str] = []

    for obj in (res.get("properties"), (rule_def or {}).get("properties")):
        if not isinstance(obj, dict):
            continue
        for k in ("cwe", "cwe_id", "cweId", "cwe_ids", "cweIds", "cwes"):
            v = obj.get(k)
            if isinstance(v, str) and v.strip():
                cands.append(v.strip())
            elif isinstance(v, list):
                cands += [str(x) for x in v if x is not None]

    taxa = res.get("taxa")
    if isinstance(taxa, list):
        for t in taxa:
            if isinstance(t, dict):
                for k in ("id", "name"):
                    v = t.get(k)
                    if isinstance(v, str) and "CWE-" in v:
                        cands.append(v)

    for t in tags:
        m = _CWE_RE.search(t)
        if m:
            cands.append(m.group(1).upper())

    seen = set()
    out: List[str] = []
    for c in cands:
        cc = str(c).strip()
        if cc and cc not in seen:
            seen.add(cc)
            out.append(cc)
    return out


def primary_location(repo_path: Path, res: Dict[str, Any]) -> Tuple[Optional[str], Optional[int], Optional[int], Optional[str]]:
    locs = res.get("locations") or []
    loc0 = locs[0] if isinstance(locs, list) and locs and isinstance(locs[0], dict) else {}
    phys = loc0.get("physicalLocation") if isinstance(loc0, dict) else None
    phys = phys if isinstance(phys, dict) else {}
    artifact = phys.get("artifactLocation") if isinstance(phys, dict) else None
    artifact = artifact if isinstance(artifact, dict) else {}
    uri = artifact.get("uri") if isinstance(artifact, dict) else None

    fp = normalize_repo_relative_path(repo_path, uri if isinstance(uri, str) else None)

    region = phys.get("region") if isinstance(phys, dict) else None
    region = region if isinstance(region, dict) else {}

    start = region.get("startLine")
    end = region.get("endLine") or start

    line_content = read_line_content(repo_path, fp, int(start)) if fp and start else None
    return fp, int(start) if start else None, int(end) if end else None, line_content
