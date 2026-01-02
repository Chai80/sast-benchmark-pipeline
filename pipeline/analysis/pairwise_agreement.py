"""pipeline.analysis.pairwise_agreement

Compute pairwise similarity and incremental coverage between tools based on a
location matrix.

This is where the benchmark becomes actionable for tool selection:
- If two tools have very high Jaccard similarity, they are redundant.
- If a tool adds many unique locations, it provides incremental coverage.
"""

from __future__ import annotations

import argparse
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from pipeline.analysis.io_utils import as_list, load_json, write_csv, write_json
from pipeline.analysis.meta_utils import with_standard_meta


def _tool_names_from_matrix(matrix: Mapping[str, Any]) -> List[str]:
    meta = matrix.get("meta") or {}
    tn = meta.get("tool_names")
    if isinstance(tn, list) and all(isinstance(x, str) for x in tn):
        return [x for x in tn if x]
    # fallback: infer from *_flagged keys on first row
    rows = matrix.get("rows") or []
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        tools = []
        for k in rows[0].keys():
            if k.endswith("_flagged"):
                tools.append(k[:-len("_flagged")])
        return sorted(set(tools))
    return []


def _signature_sets(matrix: Mapping[str, Any], tool_names: Sequence[str]) -> Dict[str, set[str]]:
    sets: Dict[str, set[str]] = {t: set() for t in tool_names}
    for r in as_list(matrix.get("rows")):
        if not isinstance(r, dict):
            continue
        sig = r.get("signature")
        if not isinstance(sig, str) or not sig:
            continue
        for t in tool_names:
            if bool(r.get(f"{t}_flagged")):
                sets[t].add(sig)
    return sets


def _counts_by_tools_flagging_count(matrix: Mapping[str, Any]) -> Dict[int, int]:
    out: Dict[int, int] = {}
    for r in as_list(matrix.get("rows")):
        if not isinstance(r, dict):
            continue
        c = r.get("tools_flagging_count")
        try:
            ci = int(c)
        except Exception:
            continue
        out[ci] = out.get(ci, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: kv[0]))


def build_pairwise_agreement(matrix_path: Path) -> Dict[str, Any]:
    matrix = load_json(matrix_path)
    tool_names = _tool_names_from_matrix(matrix)
    if not tool_names:
        raise ValueError("Could not determine tool_names from matrix meta")

    sets = _signature_sets(matrix, tool_names)

    per_tool_counts = {t: len(s) for t, s in sets.items()}

    # Pairwise rows
    rows: List[Dict[str, Any]] = []
    for a, b in combinations(tool_names, 2):
        sa = sets.get(a, set())
        sb = sets.get(b, set())
        inter = sa & sb
        union = sa | sb

        a_count = len(sa)
        b_count = len(sb)
        inter_count = len(inter)
        union_count = len(union)
        jaccard = round((inter_count / union_count), 6) if union_count else 0.0
        contain_a_in_b = round((inter_count / a_count), 6) if a_count else 0.0
        contain_b_in_a = round((inter_count / b_count), 6) if b_count else 0.0

        rows.append(
            {
                "tool_a": a,
                "tool_b": b,
                "a_count": a_count,
                "b_count": b_count,
                "intersection": inter_count,
                "union": union_count,
                "jaccard": jaccard,
                "containment_a_in_b": contain_a_in_b,
                "containment_b_in_a": contain_b_in_a,
            }
        )

    rows.sort(key=lambda r: (-(r.get("jaccard") or 0), r["tool_a"], r["tool_b"]))

    # Incremental coverage: signatures flagged only by this tool (within this matrix universe)
    # This assumes the matrix was generated with min_tools=1 (union). If not, unique counts are still valid
    # within that filtered universe.
    all_tools = tool_names
    incremental_rows: List[Dict[str, Any]] = []
    all_union = set().union(*[sets[t] for t in all_tools]) if all_tools else set()

    for t in all_tools:
        others_union = set().union(*[sets[o] for o in all_tools if o != t]) if len(all_tools) > 1 else set()
        unique = sets[t] - others_union
        incremental_rows.append(
            {
                "tool": t,
                "locations": len(sets[t]),
                "unique_locations": len(unique),
                "pct_unique": round((len(unique) / len(sets[t])) * 100.0, 2) if sets[t] else 0.0,
                "coverage_of_union_pct": round((len(sets[t]) / len(all_union)) * 100.0, 2) if all_union else 0.0,
            }
        )

    incremental_rows.sort(key=lambda r: (-r["unique_locations"], r["tool"]))

    out = {
        "meta": with_standard_meta(
            {
                "source_matrix": str(matrix_path),
                "tool_names": tool_names,
                "matrix_meta": matrix.get("meta") or {},
            },
            stage="pairwise_agreement",
            repo=((matrix.get("meta") or {}).get("repo") if isinstance(matrix.get("meta"), dict) else None),
            tool_names=tool_names,
        ),
        "summary": {
            "locations_total": len(as_list(matrix.get("rows"))),
            "counts_by_tools_flagging_count": _counts_by_tools_flagging_count(matrix),
            "per_tool_location_counts": per_tool_counts,
        },
        "pairwise": rows,
        "incremental": incremental_rows,
    }
    return out


def write_outputs(report: Dict[str, Any], out_dir: Path, name: str, formats: List[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    formats = [f.strip().lower() for f in formats if f.strip()]

    if "json" in formats:
        write_json(report, out_dir / f"{name}.json")

    if "csv" in formats:
        pairwise_rows = report.get("pairwise") or []
        inc_rows = report.get("incremental") or []
        if isinstance(pairwise_rows, list):
            write_csv([r for r in pairwise_rows if isinstance(r, dict)], out_dir / f"{name}.csv")
        if isinstance(inc_rows, list):
            write_csv([r for r in inc_rows if isinstance(r, dict)], out_dir / f"{name}_incremental.csv")


def main() -> None:
    ap = argparse.ArgumentParser(description="Compute pairwise similarity + incremental coverage from a location matrix.")
    ap.add_argument("--matrix", required=True, help="Path to hotspot location matrix JSON.")
    ap.add_argument("--out-dir", required=True, help="Output directory.")
    ap.add_argument("--name", default="pairwise_agreement", help="Base name for output files.")
    ap.add_argument("--formats", default="json,csv", help="Comma-separated formats (json,csv).")
    args = ap.parse_args()

    report = build_pairwise_agreement(Path(args.matrix))
    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    write_outputs(report, Path(args.out_dir), args.name, formats)


if __name__ == "__main__":
    main()
