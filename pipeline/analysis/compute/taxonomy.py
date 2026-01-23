from __future__ import annotations

"""Taxonomy computations (OWASP Top 10 derived counts).

The taxonomy stage turns findings into coarse OWASP buckets so we can compare
tools at a category level.

This module keeps the resolver and mapping logic away from the stage wrapper.
"""

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Mapping

from tools.normalize.classification import resolve_owasp_and_cwe


def _repo_root() -> Path:
    # .../pipeline/analysis/compute/taxonomy.py -> repo root is parents[4]
    return Path(__file__).resolve().parents[4]


def load_cwe_to_owasp_map() -> Dict[str, Any]:
    """Load the CWE->OWASP mapping JSON shipped with the repo."""

    p = _repo_root() / "mappings" / "cwe_to_owasp_top10_mitre.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    m = data.get("cwe_to_owasp") or {}
    return m if isinstance(m, dict) else {}


def _extract_tags(finding: Dict[str, Any]) -> List[str]:
    tags: List[str] = []

    # Prefer normalized fields so analysis doesn't need to parse vendor objects.
    # Include existing OWASP blocks (resolved/vendor/canonical). Their "categories"
    # strings contain year markers which allows the resolver to treat them as tags.
    for k in (
        "owasp_top_10_2017",
        "owasp_top_10_2021",
        "owasp_top_10_2017_vendor",
        "owasp_top_10_2021_vendor",
    ):
        block = finding.get(k)
        if isinstance(block, dict):
            cats = block.get("categories")
            if isinstance(cats, list):
                tags.extend([str(x) for x in cats if x is not None])

    # CWE ids are useful as tags too (resolver will normalize).
    if finding.get("cwe_id"):
        tags.append(str(finding.get("cwe_id")))
    cwe_ids = finding.get("cwe_ids")
    if isinstance(cwe_ids, list):
        tags.extend([str(x) for x in cwe_ids if x is not None])

    # Weak tags (useful when vendor metadata is sparse)
    if finding.get("rule_id"):
        tags.append(str(finding.get("rule_id")))
    if finding.get("title"):
        tags.append(str(finding.get("title")))
    if finding.get("vuln_class"):
        tags.append(str(finding.get("vuln_class")))

    return tags


def _extract_cwe_candidates(finding: Dict[str, Any]) -> List[Any]:
    cwe: List[Any] = []
    if finding.get("cwe_id"):
        cwe.append(finding.get("cwe_id"))
    ids = finding.get("cwe_ids")
    if isinstance(ids, list):
        cwe.extend([x for x in ids if x is not None])
    return cwe


def _choose_codes(resolved: Dict[str, Any], *, prefer: str = "canonical") -> List[str]:
    block = None
    if prefer == "vendor":
        block = resolved.get("owasp_top_10_2021_vendor") or resolved.get("owasp_top_10_2021")
    else:
        block = resolved.get("owasp_top_10_2021_canonical") or resolved.get("owasp_top_10_2021")

    if isinstance(block, dict):
        codes = block.get("codes") or []
        if isinstance(codes, list):
            return [str(c) for c in codes if c is not None]
    return []


def build_taxonomy_rows(
    findings_by_tool: Mapping[str, List[Dict[str, Any]]],
    *,
    cwe_to_owasp_map: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    """Build taxonomy rows.

    Returns rows shaped like `taxonomy_analysis.csv`.
    """

    counts: Dict[str, Counter] = defaultdict(Counter)
    total: Dict[str, int] = defaultdict(int)

    for tool, findings in findings_by_tool.items():
        for f in findings:
            if not isinstance(f, dict):
                continue

            resolved = resolve_owasp_and_cwe(
                tags=_extract_tags(f),
                cwe_candidates=_extract_cwe_candidates(f),
                cwe_to_owasp_map=dict(cwe_to_owasp_map),
            )
            codes = _choose_codes(resolved, prefer="canonical")  # apples-to-apples
            if not codes:
                counts[tool]["UNCLASSIFIED"] += 1
            else:
                for code in codes:
                    counts[tool][code] += 1
            total[tool] += 1

    rows: List[Dict[str, Any]] = []
    for tool in sorted(counts.keys()):
        for code, n in counts[tool].most_common():
            rows.append(
                {
                    "tool": tool,
                    "owasp_2021_code": code,
                    "count": int(n),
                    "tool_total_findings": int(total.get(tool, 0)),
                }
            )

    return rows
