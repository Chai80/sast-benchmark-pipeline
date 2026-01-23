from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json

from tools.normalize.classification import resolve_owasp_and_cwe


from ..common.findings import load_findings_by_tool
from ..common.store_keys import StoreKeys


def _repo_root() -> Path:
    # .../pipeline/analysis/stages/taxonomy.py -> repo root is parents[4]
    return Path(__file__).resolve().parents[4]


def _load_cwe_to_owasp_map() -> Dict[str, Any]:
    p = _repo_root() / "mappings" / "cwe_to_owasp_top10_mitre.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    m = data.get("cwe_to_owasp") or {}
    if not isinstance(m, dict):
        return {}
    return m


def _extract_tags(finding: Dict[str, Any]) -> List[str]:
    tags: List[str] = []
    # Prefer normalized fields so analysis doesn't need to parse vendor objects.
    #
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

    # Also include normalized title/rule_id/vuln_class as weak tags
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


@register_stage(
    "taxonomy",
    kind="analysis",
    description="Derive OWASP Top10 categories (canonical via CWE) and write taxonomy counts.",
    requires=(StoreKeys.FINDINGS_BY_TOOL,),
    produces=(StoreKeys.CWE_TO_OWASP_MAP, StoreKeys.TAXONOMY_ROWS),
)
def stage_taxonomy(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    fb = load_findings_by_tool(ctx, store)

    cwe_map = store.get(StoreKeys.CWE_TO_OWASP_MAP)
    if not isinstance(cwe_map, dict) or not cwe_map:
        cwe_map = _load_cwe_to_owasp_map()
        store.put(StoreKeys.CWE_TO_OWASP_MAP, cwe_map)

    counts: Dict[str, Counter] = defaultdict(Counter)
    total: Dict[str, int] = defaultdict(int)

    for tool, findings in fb.items():
        for f in findings:
            if not isinstance(f, dict):
                continue
            tags = _extract_tags(f)
            cwe_candidates = _extract_cwe_candidates(f)

            resolved = resolve_owasp_and_cwe(
                tags=tags,
                cwe_candidates=cwe_candidates,
                cwe_to_owasp_map=cwe_map,
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

    store.put(StoreKeys.TAXONOMY_ROWS, rows)

    out_csv = Path(ctx.out_dir) / "taxonomy_analysis.csv"
    out_json = Path(ctx.out_dir) / "taxonomy_analysis.json"
    if "csv" in ctx.formats:
        write_csv(out_csv, rows, fieldnames=["tool", "owasp_2021_code", "count", "tool_total_findings"])
        store.add_artifact("taxonomy_analysis_csv", out_csv)
    if "json" in ctx.formats:
        write_json(out_json, rows)
        store.add_artifact("taxonomy_analysis_json", out_json)

    return {"rows": len(rows)}

