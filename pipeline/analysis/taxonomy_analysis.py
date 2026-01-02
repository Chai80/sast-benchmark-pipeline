"""pipeline.analysis.taxonomy_analysis

Taxonomy analysis for *location-aligned* hotspots.

Plain English
-------------
By the time you have a hotspot_location_matrix, you've already answered:
  "Are tools pointing at the same code location?"

This stage answers the next question:
  "When tools point at the same code, do they *label* it the same way?"

We do this without re-parsing raw tool outputs:
  - Input: hotspot_location_matrix JSON (location clusters + per-tool label sets)
  - Output: a taxonomy report (CSV/JSON) that classifies each multi-tool row into
    a small number of easy-to-explain cases.

Why this is not overengineered
------------------------------
- No database
- No NLP
- No CWE hierarchy graph
- Deterministic set comparisons only

Classification cases
--------------------
For each location hotspot row with >= N tools flagging:

1) exact_match
   - Tools provide identical CWE sets (or identical OWASP sets when CWE absent)

2) enrichment_superset
   - Tools share at least one CWE (intersection non-empty), but some tools add
     extra CWE/OWASP labels. This is the most common form of "taxonomy disagreement".

3) same_owasp_diff_cwe
   - No shared CWE, but there is shared OWASP category. (Agree on high-level category.)

4) disjoint_labels
   - No overlap in CWE or OWASP. Often indicates true interpretation differences
     or that the location cluster is too wide.

5) missing_taxonomy
   - At least one tool has neither CWE nor OWASP labels for that row.

This report is meant to drive *drilldowns*:
- prioritize enrichment_superset and disjoint_labels rows for manual review
- use drilldown packs to adjudicate edge cases
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object at {path}")
    return data


def _as_str_set(v: Any) -> Set[str]:
    if isinstance(v, list):
        return {str(x) for x in v if isinstance(x, str) and x}
    if isinstance(v, str) and v:
        return {v}
    return set()


def _tool_list(row: Mapping[str, Any], tool_names: Sequence[str]) -> List[str]:
    tools = row.get("tools_flagging")
    if isinstance(tools, list):
        out = [t for t in tools if isinstance(t, str) and t in tool_names]
        if out:
            return out
    # Fallback: infer from *_flagged columns
    inferred: List[str] = []
    for t in tool_names:
        if row.get(f"{t}_flagged") is True:
            inferred.append(t)
    return inferred


def _labels_for_tool(row: Mapping[str, Any], tool: str) -> Tuple[Set[str], Set[str]]:
    """Return (cwe_set, owasp_set) for a tool on a given matrix row."""
    cwe = set()
    cwe |= _as_str_set(row.get(f"{tool}_cwe_ids_union"))
    cwe |= _as_str_set(row.get(f"{tool}_cwe_ids"))
    cwe |= _as_str_set(row.get(f"{tool}_cwe_id"))

    owasp = _as_str_set(row.get(f"{tool}_owasp_codes"))
    return cwe, owasp


def classify_taxonomy(row: Mapping[str, Any], tool_names: Sequence[str]) -> Tuple[str, str, Dict[str, Any]]:
    """Classify a location row into a taxonomy_case.

    Returns: (taxonomy_case, taxonomy_reason, derived_fields)
    """
    tools = _tool_list(row, tool_names)

    cwe_by_tool: Dict[str, Set[str]] = {}
    owasp_by_tool: Dict[str, Set[str]] = {}

    for t in tools:
        cwe_set, owasp_set = _labels_for_tool(row, t)
        cwe_by_tool[t] = cwe_set
        owasp_by_tool[t] = owasp_set

    # If any tool has neither CWE nor OWASP labels, we can't do a meaningful set comparison.
    missing_tools = [t for t in tools if not cwe_by_tool[t] and not owasp_by_tool[t]]
    if missing_tools:
        return (
            "missing_taxonomy",
            f"Missing CWE/OWASP labels for: {', '.join(missing_tools)}",
            {
                "cwe_union": sorted(set().union(*cwe_by_tool.values()) if cwe_by_tool else set()),
                "cwe_intersection": [],
                "owasp_union": sorted(set().union(*owasp_by_tool.values()) if owasp_by_tool else set()),
                "owasp_intersection": [],
            },
        )

    # Compute unions/intersections across non-empty sets (to avoid empties from tools that don't provide that label type)
    cwe_sets = [s for s in cwe_by_tool.values() if s]
    owasp_sets = [s for s in owasp_by_tool.values() if s]

    cwe_union = set().union(*cwe_sets) if cwe_sets else set()
    owasp_union = set().union(*owasp_sets) if owasp_sets else set()

    cwe_intersection = set(cwe_sets[0]).intersection(*cwe_sets[1:]) if len(cwe_sets) >= 2 else set()
    owasp_intersection = set(owasp_sets[0]).intersection(*owasp_sets[1:]) if len(owasp_sets) >= 2 else set()

    # Exact match: prefer CWE if available, otherwise OWASP.
    if cwe_sets and all(s == cwe_sets[0] for s in cwe_sets) and cwe_sets[0]:
        return (
            "exact_match",
            "All tools provide identical CWE sets",
            {
                "cwe_union": sorted(cwe_union),
                "cwe_intersection": sorted(cwe_intersection),
                "owasp_union": sorted(owasp_union),
                "owasp_intersection": sorted(owasp_intersection),
            },
        )
    if (not cwe_sets) and owasp_sets and all(s == owasp_sets[0] for s in owasp_sets) and owasp_sets[0]:
        return (
            "exact_match",
            "All tools provide identical OWASP sets (no CWE available)",
            {
                "cwe_union": [],
                "cwe_intersection": [],
                "owasp_union": sorted(owasp_union),
                "owasp_intersection": sorted(owasp_intersection),
            },
        )

    # Enrichment: shared CWE core exists, but sets differ
    if cwe_intersection:
        return (
            "enrichment_superset",
            "Tools share at least one CWE, but some add extra labels",
            {
                "cwe_union": sorted(cwe_union),
                "cwe_intersection": sorted(cwe_intersection),
                "owasp_union": sorted(owasp_union),
                "owasp_intersection": sorted(owasp_intersection),
            },
        )

    # Same OWASP, different CWE
    if owasp_intersection:
        return (
            "same_owasp_diff_cwe",
            "Tools share OWASP category but not CWE",
            {
                "cwe_union": sorted(cwe_union),
                "cwe_intersection": [],
                "owasp_union": sorted(owasp_union),
                "owasp_intersection": sorted(owasp_intersection),
            },
        )

    return (
        "disjoint_labels",
        "No overlap in CWE or OWASP label sets",
        {
            "cwe_union": sorted(cwe_union),
            "cwe_intersection": [],
            "owasp_union": sorted(owasp_union),
            "owasp_intersection": [],
        },
    )


def build_taxonomy_report(matrix_path: Path, *, min_tools: int = 2) -> Dict[str, Any]:
    matrix = _load_json(matrix_path)
    meta = matrix.get("meta") if isinstance(matrix.get("meta"), dict) else {}
    rows = matrix.get("rows") if isinstance(matrix.get("rows"), list) else []
    tool_names = meta.get("tool_names") if isinstance(meta.get("tool_names"), list) else []

    if not tool_names:
        raise ValueError("Matrix meta.tool_names missing; pass hotspot_location_matrix JSON")

    out_rows: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {}

    for r in rows:
        if not isinstance(r, dict):
            continue
        if int(r.get("tools_flagging_count") or 0) < int(min_tools):
            continue

        case, reason, derived = classify_taxonomy(r, tool_names)

        out = {
            "signature": r.get("signature"),
            "file": r.get("file"),
            "cluster_start": r.get("cluster_start"),
            "cluster_end": r.get("cluster_end"),
            "tools_flagging_count": r.get("tools_flagging_count"),
            "tools_flagging": r.get("tools_flagging"),
            "taxonomy_disagreement_owasp": r.get("taxonomy_disagreement"),
            "taxonomy_case": case,
            "taxonomy_reason": reason,
            "cwe_intersection": derived.get("cwe_intersection", []),
            "cwe_union": derived.get("cwe_union", []),
            "owasp_intersection": derived.get("owasp_intersection", []),
            "owasp_union": derived.get("owasp_union", []),
        }
        out_rows.append(out)
        counts[case] = counts.get(case, 0) + 1

    report = {
        "meta": {
            "source_matrix": str(matrix_path),
            "min_tools": int(min_tools),
            "tool_names": tool_names,
            "matrix_meta": meta,
        },
        "summary": {"counts_by_case": counts, "rows": len(out_rows)},
        "rows": out_rows,
    }
    return report


def write_outputs(report: Dict[str, Any], out_dir: Path, name: str, formats: Sequence[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    formats_norm = [f.strip().lower() for f in formats if f and f.strip()]

    if "json" in formats_norm:
        (out_dir / f"{name}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    if "csv" in formats_norm:
        rows = report.get("rows") or []
        if not rows:
            # Still write an empty header for consistency
            fieldnames = [
                "signature",
                "file",
                "cluster_start",
                "cluster_end",
                "tools_flagging_count",
                "tools_flagging",
                "taxonomy_disagreement_owasp",
                "taxonomy_case",
                "taxonomy_reason",
                "cwe_intersection",
                "cwe_union",
                "owasp_intersection",
                "owasp_union",
            ]
            with (out_dir / f"{name}.csv").open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
            return

        # Stable columns
        fieldnames = [
            "signature",
            "file",
            "cluster_start",
            "cluster_end",
            "tools_flagging_count",
            "tools_flagging",
            "taxonomy_disagreement_owasp",
            "taxonomy_case",
            "taxonomy_reason",
            "cwe_intersection",
            "cwe_union",
            "owasp_intersection",
            "owasp_union",
        ]

        with (out_dir / f"{name}.csv").open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)


def main() -> None:
    ap = argparse.ArgumentParser(description="Classify taxonomy differences for location-aligned hotspots.")
    ap.add_argument("--matrix", required=True, help="Path to hotspot_location_matrix JSON (location clusters)")
    ap.add_argument("--out-dir", required=True, help="Output directory for taxonomy report files")
    ap.add_argument(
        "--name",
        default="taxonomy_analysis",
        help="Base name for output files (default: taxonomy_analysis)",
    )
    ap.add_argument(
        "--formats",
        default="json,csv",
        help="Comma-separated list of output formats (json,csv).",
    )
    ap.add_argument(
        "--min-tools",
        type=int,
        default=2,
        help="Only analyze rows flagged by at least N tools (default: 2).",
    )

    args = ap.parse_args()

    matrix_path = Path(args.matrix)
    out_dir = Path(args.out_dir)
    formats = [s.strip() for s in str(args.formats).split(",") if s.strip()]

    report = build_taxonomy_report(matrix_path, min_tools=int(args.min_tools))
    write_outputs(report, out_dir, str(args.name), formats)


if __name__ == "__main__":
    main()
