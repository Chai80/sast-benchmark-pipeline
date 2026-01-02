"""pipeline.analysis.triage_queue

Generate a prioritized "triage queue" of code locations to manually review.

Goal
----
Turn matrices into action:

- Where do tools genuinely disagree (disjoint labels at same location)?
- Where might a tool be missing something (single-tool-only, high severity)?
- Where are we blocked by missing metadata (missing_taxonomy)?

This produces a simple CSV/JSON list you can hand to a reviewer without a DB.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from pipeline.analysis.io_utils import as_list, load_json, write_csv, write_json


_SEV_WEIGHT = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def _sev_weight(sev: Optional[str]) -> int:
    if not isinstance(sev, str):
        return 0
    return _SEV_WEIGHT.get(sev.strip().upper(), 0)


def _max_severity_for_row(row: Mapping[str, Any], tool_names: Sequence[str]) -> Optional[str]:
    best: Optional[str] = None
    best_w = -1
    for t in tool_names:
        if not bool(row.get(f"{t}_flagged")):
            continue
        sev = row.get(f"{t}_severity")
        if isinstance(sev, str):
            w = _sev_weight(sev)
            if w > best_w:
                best_w = w
                best = sev.strip().upper()
    return best


def _tool_names_from_matrix(matrix: Mapping[str, Any]) -> List[str]:
    meta = matrix.get("meta") or {}
    tn = meta.get("tool_names")
    if isinstance(tn, list) and all(isinstance(x, str) for x in tn):
        return [x for x in tn if x]
    return []


def _taxonomy_map(taxonomy: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    out: Dict[str, Mapping[str, Any]] = {}
    for r in as_list(taxonomy.get("rows")):
        if not isinstance(r, dict):
            continue
        sig = r.get("signature")
        if isinstance(sig, str) and sig:
            out[sig] = r
    return out


def _priority_score(
    *,
    tools_flagging_count: int,
    max_sev: Optional[str],
    taxonomy_case: Optional[str],
    taxonomy_disagreement_owasp: Optional[bool],
) -> int:
    score = 0

    # Severity baseline
    score += _sev_weight(max_sev)

    # Candidate detection misses / unique coverage
    if tools_flagging_count == 1:
        score += 4

    # Taxonomy conflicts
    if taxonomy_case == "disjoint_labels":
        score += 5
        if tools_flagging_count >= 3:
            score += 2

    # Missing metadata blocks normalization
    if taxonomy_case == "missing_taxonomy":
        score += 2

    # OWASP disagreement heuristic (from taxonomy analysis)
    if taxonomy_disagreement_owasp:
        score += 1

    # Exact match is lower triage value unless severity is high
    if taxonomy_case == "exact_match":
        score -= 1

    return score


def build_triage_queue(matrix_path: Path, taxonomy_path: Optional[Path] = None, *, limit: int = 200) -> Dict[str, Any]:
    matrix = load_json(matrix_path)
    tool_names = _tool_names_from_matrix(matrix)

    # Scope hint (best-effort):
    # For each tool, track which files show *any* finding in this matrix.
    # If a tool never appears in a given file, a "miss" at a location may be
    # scope/config (file type not analyzed) rather than detection.
    files_with_findings_by_tool: Dict[str, set[str]] = {t: set() for t in tool_names}
    for rr in as_list(matrix.get("rows")):
        if not isinstance(rr, dict):
            continue
        fp_any = rr.get("file")
        if not isinstance(fp_any, str) or not fp_any:
            continue
        for t in tool_names:
            if bool(rr.get(f"{t}_flagged")):
                files_with_findings_by_tool[t].add(fp_any)


    taxonomy: Dict[str, Any] = {}
    tax_map: Dict[str, Mapping[str, Any]] = {}
    if taxonomy_path:
        taxonomy = load_json(taxonomy_path)
        tax_map = _taxonomy_map(taxonomy)

    rows_out: List[Dict[str, Any]] = []

    for r in as_list(matrix.get("rows")):
        if not isinstance(r, dict):
            continue
        sig = r.get("signature")
        if not isinstance(sig, str) or not sig:
            continue

        tools_flagging = r.get("tools_flagging")
        if not isinstance(tools_flagging, list):
            tools_flagging = [t for t in tool_names if bool(r.get(f"{t}_flagged"))]

        try:
            tcount = int(r.get("tools_flagging_count") or len(tools_flagging))
        except Exception:
            tcount = len(tools_flagging)

        if tcount <= 0:
            continue

        max_sev = _max_severity_for_row(r, tool_names)

        tax_row = tax_map.get(sig)
        taxonomy_case = tax_row.get("taxonomy_case") if isinstance(tax_row, dict) else None
        taxonomy_reason = tax_row.get("taxonomy_reason") if isinstance(tax_row, dict) else None
        taxonomy_disagreement_owasp = (
            bool(tax_row.get("taxonomy_disagreement_owasp")) if isinstance(tax_row, dict) else None
        )


        file_path = r.get("file")
        tools_no_findings_in_file: List[str] = []
        if isinstance(file_path, str) and file_path:
            for t in tool_names:
                if bool(r.get(f"{t}_flagged")):
                    continue
                if file_path not in files_with_findings_by_tool.get(t, set()):
                    tools_no_findings_in_file.append(t)

        score = _priority_score(
            tools_flagging_count=tcount,
            max_sev=max_sev,
            taxonomy_case=taxonomy_case if isinstance(taxonomy_case, str) else None,
            taxonomy_disagreement_owasp=taxonomy_disagreement_owasp,
        )

        # Suggested action (plain English)
        if tcount == 1:
            action = "Candidate unique: verify true miss vs scope/config"
        elif taxonomy_case == "disjoint_labels":
            action = "Taxonomy conflict: inspect code context and tool evidence"
        elif taxonomy_case == "missing_taxonomy":
            action = "Missing taxonomy: improve mapping/normalization for at least one tool"
        elif taxonomy_case == "enrichment_superset":
            action = "Label enrichment: tools likely agree; check CWE/OWASP mapping inflation"
        elif taxonomy_case == "exact_match":
            action = "Consensus: low triage value (use as control set)"
        else:
            action = "Overlap: inspect if needed"

        rows_out.append(
            {
                "priority_score": score,
                "signature": sig,
                "file": r.get("file"),
                "cluster_start": r.get("cluster_start"),
                "cluster_end": r.get("cluster_end"),
                "tools_flagging_count": tcount,
                "tools_flagging": tools_flagging,
                "max_severity": max_sev,
                "taxonomy_case": taxonomy_case,
                "taxonomy_reason": taxonomy_reason,
                "suggested_action": action,
                "tools_no_findings_in_file": tools_no_findings_in_file,

            }
        )

    rows_out.sort(key=lambda rr: (-(rr.get("priority_score") or 0), str(rr.get("file") or ""), rr.get("cluster_start") or 0))

    if limit and limit > 0:
        rows_out = rows_out[:limit]

    out = {
        "meta": {
            "source_matrix": str(matrix_path),
            "source_taxonomy": str(taxonomy_path) if taxonomy_path else None,
            "tool_names": tool_names,
        },
        "summary": {
            "rows": len(rows_out),
            "limit": limit,
        },
        "rows": rows_out,
    }
    return out


def write_outputs(report: Dict[str, Any], out_dir: Path, name: str, formats: List[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    formats = [f.strip().lower() for f in formats if f.strip()]

    if "json" in formats:
        write_json(report, out_dir / f"{name}.json")

    if "csv" in formats:
        rows = report.get("rows") or []
        if isinstance(rows, list):
            write_csv([r for r in rows if isinstance(r, dict)], out_dir / f"{name}.csv")


def main() -> None:
    ap = argparse.ArgumentParser(description="Build a prioritized triage queue from a location matrix (+ optional taxonomy report).")
    ap.add_argument("--matrix", required=True, help="Path to hotspot location matrix JSON.")
    ap.add_argument("--taxonomy", help="Path to taxonomy_analysis.json (optional).")
    ap.add_argument("--out-dir", required=True, help="Output directory.")
    ap.add_argument("--name", default="triage_queue", help="Base name for output files.")
    ap.add_argument("--formats", default="json,csv", help="Comma-separated formats (json,csv).")
    ap.add_argument("--limit", type=int, default=200, help="Max rows to include (default: 200).")
    args = ap.parse_args()

    report = build_triage_queue(Path(args.matrix), Path(args.taxonomy) if args.taxonomy else None, limit=args.limit)
    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    write_outputs(report, Path(args.out_dir), args.name, formats)


if __name__ == "__main__":
    main()
