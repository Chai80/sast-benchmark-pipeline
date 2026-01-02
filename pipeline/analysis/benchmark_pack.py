"""pipeline.analysis.benchmark_pack

Create a single "benchmark pack" artifact that summarizes the key outcomes of
a run:

- location-level overlap (agreement vs unique)
- incremental coverage per tool
- taxonomy disagreement breakdown (if taxonomy report provided)
- tool output quality profile (if provided or computed)
- pairwise similarity (if provided or computed)
- a short list of example signatures to anchor discussion

This is designed for Victor / stakeholders: a single JSON (plus a couple CSVs)
that is easy to share and interpret.

No dashboards, no DB.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from pipeline.analysis.io_utils import as_list, load_json, write_csv, write_json
from pipeline.analysis.meta_utils import with_standard_meta

# Optional imports (avoid circulars in simple module usage)
from pipeline.analysis.tool_profile import build_tool_profile
from pipeline.analysis.pairwise_agreement import build_pairwise_agreement
from pipeline.analysis.triage_queue import build_triage_queue


def _tool_names_from_matrix(matrix: Mapping[str, Any]) -> List[str]:
    meta = matrix.get("meta") or {}
    tn = meta.get("tool_names")
    if isinstance(tn, list) and all(isinstance(x, str) for x in tn):
        return [x for x in tn if x]
    return []


def _sev_weight(sev: Optional[str]) -> int:
    if not isinstance(sev, str):
        return 0
    s = sev.strip().upper()
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(s, 0)


def _counts_by_tools_flagging_count(matrix: Mapping[str, Any]) -> Dict[int, int]:
    out: Dict[int, int] = {}
    for r in as_list(matrix.get("rows")):
        if not isinstance(r, dict):
            continue
        try:
            c = int(r.get("tools_flagging_count") or 0)
        except Exception:
            continue
        out[c] = out.get(c, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: kv[0]))


def _per_tool_counts(matrix: Mapping[str, Any], tool_names: Sequence[str]) -> Tuple[Dict[str, int], Dict[str, int]]:
    total: Dict[str, int] = {t: 0 for t in tool_names}
    unique: Dict[str, int] = {t: 0 for t in tool_names}

    for r in as_list(matrix.get("rows")):
        if not isinstance(r, dict):
            continue
        try:
            c = int(r.get("tools_flagging_count") or 0)
        except Exception:
            c = 0
        for t in tool_names:
            if bool(r.get(f"{t}_flagged")):
                total[t] += 1
                if c == 1:
                    unique[t] += 1
    return total, unique


def _example_rows(matrix: Mapping[str, Any], tool_names: Sequence[str], *, max_items: int = 10) -> Dict[str, List[Dict[str, Any]]]:
    n_tools = len(tool_names)

    consensus: List[Dict[str, Any]] = []
    unique_high: List[Dict[str, Any]] = []
    disjoint: List[Dict[str, Any]] = []  # placeholder; filled if taxonomy report provided later

    for r in as_list(matrix.get("rows")):
        if not isinstance(r, dict):
            continue
        sig = r.get("signature")
        if not isinstance(sig, str) or not sig:
            continue
        try:
            c = int(r.get("tools_flagging_count") or 0)
        except Exception:
            c = 0

        if c == n_tools:
            consensus.append({"signature": sig, "file": r.get("file"), "cluster_start": r.get("cluster_start"), "cluster_end": r.get("cluster_end"), "tools_flagging": r.get("tools_flagging")})
        if c == 1:
            # pick max severity (best-effort)
            max_sev = None
            max_w = -1
            for t in tool_names:
                if not bool(r.get(f"{t}_flagged")):
                    continue
                sev = r.get(f"{t}_severity")
                if isinstance(sev, str):
                    w = _sev_weight(sev)
                    if w > max_w:
                        max_w = w
                        max_sev = sev.strip().upper()
            unique_high.append({"signature": sig, "file": r.get("file"), "cluster_start": r.get("cluster_start"), "cluster_end": r.get("cluster_end"), "tools_flagging": r.get("tools_flagging"), "max_severity": max_sev, "severity_weight": max_w})

    # Deterministic ordering
    consensus.sort(key=lambda x: (str(x.get("file") or ""), x.get("cluster_start") or 0))
    unique_high.sort(key=lambda x: (-(x.get("severity_weight") or 0), str(x.get("file") or ""), x.get("cluster_start") or 0))

    return {
        "consensus_all_tools": consensus[:max_items],
        "unique_single_tool_high_severity": unique_high[:max_items],
        "taxonomy_disjoint_labels": disjoint,  # filled later
    }


def _load_tool_run_meta(tool_inputs: Mapping[str, str]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    commits: set[str] = set()

    for tool, inp in sorted(tool_inputs.items(), key=lambda kv: kv[0]):
        data = load_json(Path(inp))

        # best-effort meta extraction
        tool_version = data.get("tool_version")
        scan = data.get("scan") if isinstance(data.get("scan"), dict) else {}
        run_id = scan.get("run_id")
        scan_date = scan.get("scan_date")
        tr = data.get("target_repo") if isinstance(data.get("target_repo"), dict) else {}
        commit = tr.get("commit")
        if isinstance(commit, str) and commit:
            commits.add(commit)

        rows.append(
            {
                "tool": tool,
                "tool_version": tool_version,
                "run_id": run_id,
                "scan_date": scan_date,
                "commit": commit,
                "normalized_json": inp,
            }
        )

    commit_consistent = len(commits) <= 1
    commit_value = next(iter(commits)) if len(commits) == 1 else None

    return rows, {"commit_consistent": commit_consistent, "commit": commit_value}


def build_benchmark_pack(
    *,
    matrix_path: Path,
    out_dir: Optional[Path] = None,
    taxonomy_path: Optional[Path] = None,
    mode_for_profiles: str = "security",
    max_examples: int = 10,
) -> Dict[str, Any]:
    matrix = load_json(matrix_path)
    tool_names = _tool_names_from_matrix(matrix)
    meta = matrix.get("meta") or {}
    tool_inputs = meta.get("tool_inputs") if isinstance(meta.get("tool_inputs"), dict) else {}

    # Core overlap stats
    counts_by_k = _counts_by_tools_flagging_count(matrix)
    per_tool_total, per_tool_unique = _per_tool_counts(matrix, tool_names)

    examples = _example_rows(matrix, tool_names, max_items=max_examples)

    # Tool run meta (commit alignment, scan dates)
    tool_runs, commit_meta = _load_tool_run_meta(tool_inputs)

    # Optional: taxonomy summary
    taxonomy: Dict[str, Any] = {}
    taxonomy_summary: Dict[str, Any] = {}
    taxonomy_rows_by_sig: Dict[str, Mapping[str, Any]] = {}
    if taxonomy_path:
        taxonomy = load_json(taxonomy_path)
        taxonomy_summary = taxonomy.get("summary") if isinstance(taxonomy.get("summary"), dict) else {}
        for r in as_list(taxonomy.get("rows")):
            if isinstance(r, dict) and isinstance(r.get("signature"), str):
                taxonomy_rows_by_sig[r["signature"]] = r

        # Fill disjoint examples (top by tools_flagging_count)
        disjoint = [r for r in taxonomy_rows_by_sig.values() if r.get("taxonomy_case") == "disjoint_labels"]
        disjoint.sort(key=lambda rr: (-(rr.get("tools_flagging_count") or 0), str(rr.get("file") or ""), rr.get("cluster_start") or 0))
        examples["taxonomy_disjoint_labels"] = [
            {
                "signature": rr.get("signature"),
                "file": rr.get("file"),
                "cluster_start": rr.get("cluster_start"),
                "cluster_end": rr.get("cluster_end"),
                "tools_flagging": rr.get("tools_flagging"),
                "cwe_union": rr.get("cwe_union"),
                "owasp_union": rr.get("owasp_union"),
            }
            for rr in disjoint[:max_examples]
        ]

        # Core CWE agreement rates
        denom = 0
        denom_non_missing = 0
        num_intersection_nonempty = 0
        num_intersection_nonempty_non_missing = 0
        for rr in taxonomy_rows_by_sig.values():
            denom += 1
            case = rr.get("taxonomy_case")
            cwe_i = rr.get("cwe_intersection")
            has_i = isinstance(cwe_i, list) and len(cwe_i) > 0
            if has_i:
                num_intersection_nonempty += 1
            if case != "missing_taxonomy":
                denom_non_missing += 1
                if has_i:
                    num_intersection_nonempty_non_missing += 1

        taxonomy_summary = dict(taxonomy_summary)  # copy
        taxonomy_summary.update(
            {
                "cwe_intersection_nonempty_rate": round((num_intersection_nonempty / denom), 4) if denom else 0.0,
                "cwe_intersection_nonempty_rate_excluding_missing_taxonomy": round((num_intersection_nonempty_non_missing / denom_non_missing), 4)
                if denom_non_missing
                else 0.0,
            }
        )

    # Derived: per tool summary rows (useful for CSV)
    tool_summary_rows: List[Dict[str, Any]] = []
    for t in tool_names:
        total = per_tool_total.get(t, 0)
        unique = per_tool_unique.get(t, 0)
        tool_summary_rows.append(
            {
                "tool": t,
                "locations_flagged": total,
                "unique_locations": unique,
                "pct_unique": round((unique / total) * 100.0, 2) if total else 0.0,
                "coverage_of_union_pct": round((total / len(as_list(matrix.get("rows")))) * 100.0, 2) if as_list(matrix.get("rows")) else 0.0,
            }
        )
    tool_summary_rows.sort(key=lambda r: (-r["unique_locations"], r["tool"]))

    # Compute/attach tool_profile + pairwise + triage (embedded for convenience)
    tool_profile = build_tool_profile(matrix_path=matrix_path, report_path=None, mode=mode_for_profiles)
    pairwise = build_pairwise_agreement(matrix_path)
    triage = build_triage_queue(matrix_path, taxonomy_path, limit=200)

    out = {
        "meta": with_standard_meta(
            {
                "source_matrix": str(matrix_path),
                "source_taxonomy": str(taxonomy_path) if taxonomy_path else None,
                "repo": meta.get("repo"),
                "mode": meta.get("mode"),
                "tolerance": meta.get("tolerance"),
                "signature_type": meta.get("signature_type"),
                "tool_names": tool_names,
                "tool_inputs": tool_inputs,
            },
            stage="benchmark_pack",
            repo=(meta.get("repo") if isinstance(meta.get("repo"), str) else None),
            tool_names=tool_names,
            mode=meta.get("mode"),
            tolerance=meta.get("tolerance"),
            signature_type=meta.get("signature_type"),
        ),
        "run_meta": {
            "tools": tool_runs,
            **commit_meta,
        },
        "overlap": {
            "counts_by_tools_flagging_count": counts_by_k,
            "locations_total": len(as_list(matrix.get("rows"))),
        },
        "per_tool": {
            "location_counts": per_tool_total,
            "unique_location_counts": per_tool_unique,
            "rows": tool_summary_rows,
        },
        "taxonomy": taxonomy_summary if taxonomy_summary else None,
        "pairwise": pairwise.get("pairwise") if isinstance(pairwise, dict) else None,
        "incremental": pairwise.get("incremental") if isinstance(pairwise, dict) else None,
        "tool_profile": tool_profile.get("rows") if isinstance(tool_profile, dict) else None,
        "triage_queue_top": triage.get("rows")[:20] if isinstance(triage.get("rows"), list) else None,
        "examples": examples,
    }

    return out


def write_outputs(pack: Dict[str, Any], out_dir: Path, name: str, formats: List[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    formats = [f.strip().lower() for f in formats if f.strip()]

    if "json" in formats:
        write_json(pack, out_dir / f"{name}.json")

    if "csv" in formats:
        # per-tool summary
        per_tool_rows = (pack.get("per_tool") or {}).get("rows") or []
        if isinstance(per_tool_rows, list):
            write_csv([r for r in per_tool_rows if isinstance(r, dict)], out_dir / f"{name}_tools.csv")

        # overlap distribution
        overlap = (pack.get("overlap") or {}).get("counts_by_tools_flagging_count") or {}
        if isinstance(overlap, dict):
            overlap_rows = [{"tools_flagging_count": k, "locations": v} for k, v in overlap.items()]
            write_csv(overlap_rows, out_dir / f"{name}_overlap.csv")


def main() -> None:
    ap = argparse.ArgumentParser(description="Build a single benchmark summary pack (JSON + optional CSVs).")
    ap.add_argument("--matrix", required=True, help="Path to hotspot location matrix JSON (ideally min_tools=1 union).")
    ap.add_argument("--taxonomy", help="Path to taxonomy_analysis.json (optional).")
    ap.add_argument("--out-dir", required=True, help="Output directory.")
    ap.add_argument("--name", default="benchmark_pack", help="Base name for output files.")
    ap.add_argument("--formats", default="json,csv", help="Comma-separated formats (json,csv).")
    ap.add_argument("--mode", choices=["security", "all"], default="security", help="Filtering mode used for tool_profile (default: security).")
    ap.add_argument("--max-examples", type=int, default=10, help="Max examples per category to embed (default: 10).")

    args = ap.parse_args()
    pack = build_benchmark_pack(
        matrix_path=Path(args.matrix),
        taxonomy_path=Path(args.taxonomy) if args.taxonomy else None,
        mode_for_profiles=args.mode,
        max_examples=args.max_examples,
    )
    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    write_outputs(pack, Path(args.out_dir), args.name, formats)


if __name__ == "__main__":
    main()
