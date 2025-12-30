"""tools/snyk/vendor_rules.py

Optional offline mapping for Snyk rule -> (OWASP-2021, CWE) enrichment.

The repo keeps a mapping file under mappings/ to compensate for SARIF
payloads that omit CWE/OWASP tags.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tools.core import ROOT_DIR, read_json

VendorRuleIndex = Dict[str, Dict[str, List[str]]]


def load_snyk_vendor_rule_index() -> VendorRuleIndex:
    candidates = [
        ROOT_DIR / "mappings" / "snyk_rule_to_owasp_2021.json",
        ROOT_DIR / "mappings" / "snyk_rule_to_owasp_top10_2021.json",
        ROOT_DIR / "mappings" / "snyk_to_owasp_2021.json",
    ]

    def norm_key(s: str) -> str:
        return " ".join(s.strip().lower().replace("_", " ").split())

    def as_str_list(v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return [str(x) for x in v if x is not None]
        return []

    def put(idx: VendorRuleIndex, key: str, *, owasp2021: List[str], cwe_ids: List[str]) -> None:
        if not key:
            return
        if not (owasp2021 or cwe_ids):
            return
        idx[key] = {"owasp_top_10_2021": owasp2021, "cwe_ids": cwe_ids}

    for p in candidates:
        if not p.exists():
            continue
        try:
            data = read_json(p)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue

        idx: VendorRuleIndex = {}

        languages = data.get("languages")
        if isinstance(languages, dict):
            for _lang, rules in languages.items():
                if not isinstance(rules, dict):
                    continue
                for rname, info in rules.items():
                    if not isinstance(rname, str) or not rname.strip():
                        continue
                    if not isinstance(info, dict):
                        continue
                    owasp2021 = as_str_list(
                        info.get("owasp_top_10_2021") or info.get("owasp_2021") or info.get("owasp2021")
                    )
                    cwe_ids = as_str_list(info.get("cwe_ids") or info.get("cwe") or info.get("cweIds"))
                    put(idx, rname, owasp2021=owasp2021, cwe_ids=cwe_ids)
                    put(idx, norm_key(rname), owasp2021=owasp2021, cwe_ids=cwe_ids)

        for k, v in data.items():
            if not isinstance(k, str):
                continue
            if k in {"_meta", "aliases", "languages", "rules"}:
                continue
            if isinstance(v, list):
                put(idx, k, owasp2021=[str(x) for x in v if x is not None], cwe_ids=[])
            elif isinstance(v, dict):
                codes = as_str_list(v.get("owasp_2021") or v.get("owasp_top_10_2021") or v.get("owasp2021"))
                cwe_ids = as_str_list(v.get("cwe_ids") or v.get("cwe") or v.get("cweIds"))
                put(idx, k, owasp2021=codes, cwe_ids=cwe_ids)
                if isinstance(v.get("name"), str) and v.get("name").strip():
                    put(idx, norm_key(v["name"]), owasp2021=codes, cwe_ids=cwe_ids)

        rules = data.get("rules")
        if isinstance(rules, list):
            for r in rules:
                if not isinstance(r, dict):
                    continue
                rid = r.get("id") or r.get("rule_id")
                name = r.get("name")
                codes = as_str_list(r.get("owasp_2021") or r.get("owasp_top_10_2021") or r.get("owasp2021"))
                cwe_ids = as_str_list(r.get("cwe_ids") or r.get("cwe") or r.get("cweIds"))
                if isinstance(rid, str) and rid.strip():
                    put(idx, rid.strip(), owasp2021=codes, cwe_ids=cwe_ids)
                if isinstance(name, str) and name.strip():
                    put(idx, name.strip(), owasp2021=codes, cwe_ids=cwe_ids)
                    put(idx, norm_key(name), owasp2021=codes, cwe_ids=cwe_ids)

        if idx:
            return idx

    return {}


def load_snyk_vendor_owasp_2021_index() -> VendorRuleIndex:
    return load_snyk_vendor_rule_index()


def vendor_rule_info(vendor_idx: VendorRuleIndex, rule_id: Optional[str], rule_name: Optional[str]) -> Tuple[List[str], List[str]]:
    if not vendor_idx:
        return [], []

    def norm_key(s: str) -> str:
        return " ".join(s.strip().lower().replace("_", " ").split())

    info = None
    if rule_id and rule_id in vendor_idx:
        info = vendor_idx.get(rule_id)
    if info is None and rule_name:
        info = vendor_idx.get(rule_name) or vendor_idx.get(norm_key(rule_name))

    if not isinstance(info, dict):
        return [], []
    return info.get("owasp_top_10_2021") or [], info.get("cwe_ids") or []
