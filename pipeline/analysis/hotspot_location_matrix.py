"""pipeline.analysis.hotspot_location_matrix

Build a union-sized hotspot matrix using a *location-based* signature.

This is the next step after hotspot_matrix.py:

- hotspot_matrix.py aligns on (file, OWASP-2021) -> coarse overlap.
- hotspot_location_matrix.py aligns on (file, line_cluster) -> granular overlap.

The point is to distinguish:
- taxonomy disagreement: same code location, different labels
- detection disagreement: one tool truly doesn't raise anything at that code location
- scope/config differences: tools don't scan the same things (e.g. Sonar CODE_SMELLs)

Signature
---------
We use *line-tolerance clustering* instead of fixed buckets to avoid bucket
boundary artifacts.

    (normalize_file_path(file_path, repo_name), line_cluster)

Where line_cluster is computed by:
  - collecting all tools' anchor lines in a file
  - clustering nearby anchors together if they are within --tolerance lines

Signature id format:
    routes/search.ts|L21-30

Outputs
-------
- JSON matrix (recommended for downstream tooling)
- CSV matrix (spreadsheet-friendly)

This script is filesystem-only; no database required.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from pipeline.analysis.io_utils import as_list, load_json, write_csv, write_json
from pipeline.analysis.meta_utils import with_standard_meta
from pipeline.analysis.finding_filters import filter_findings
from pipeline.analysis.location_signatures import build_location_cluster_index
from pipeline.analysis.unique_overview import canonical_owasp_2021_codes
from pipeline.core import ROOT_DIR as REPO_ROOT_DIR


def _extract_repo_name(data: Mapping[str, Any], fallback: Optional[str]) -> Optional[str]:
    tr = data.get("target_repo")
    rn = tr.get("name") if isinstance(tr, dict) else None
    if not isinstance(rn, str) or not rn:
        return fallback
    return rn




def build_hotspot_location_matrix(
    report_path: Path,
    *,
    tolerance: int = 3,
    mode: str = "security",
    cwe_map_path: Path = REPO_ROOT_DIR / "mappings" / "cwe_to_owasp_top10_mitre.json",
    min_tools: int = 1,
) -> Dict[str, Any]:
    """Build a location-based hotspot matrix from a unique_overview report."""

    report = load_json(report_path)
    tools_meta: Dict[str, Dict[str, Any]] = report.get("tools", {})
    repo_name = report.get("repo") if isinstance(report.get("repo"), str) else None

    if not tools_meta:
        raise ValueError("Report missing 'tools' metadata. Did you pass the right JSON?")
    if tolerance < 0:
        raise ValueError("tolerance must be >= 0")

    # Load CWE->OWASP mapping (reused for per-location taxonomy comparison)
    cwe_map: Mapping[str, Any] = load_json(cwe_map_path)

    tool_names = sorted(tools_meta.keys())

    # Load findings per tool
    findings_by_tool: Dict[str, List[Mapping[str, Any]]] = {}
    repo_name_by_tool: Dict[str, Optional[str]] = {}

    tool_inputs: Dict[str, str] = {}

    for tool, meta in tools_meta.items():
        input_path = meta.get("input")
        if not isinstance(input_path, str) or not input_path:
            raise ValueError(f"Tool '{tool}' missing tools[tool].input in report.")
        tool_inputs[tool] = input_path

        data = load_json(Path(input_path))
        findings = [f for f in as_list(data.get("findings")) if isinstance(f, dict)]
        findings = filter_findings(tool, findings, mode=mode)

        findings_by_tool[tool] = findings
        repo_name_by_tool[tool] = _extract_repo_name(data, repo_name)

    # Build canonical clusters across tools (prevents per-tool cluster drift)
    clusters, idx_by_tool = build_location_cluster_index(
        findings_by_tool=findings_by_tool,
        repo_name_by_tool=repo_name_by_tool,
        tolerance=int(tolerance),
    )

    rows: List[Dict[str, Any]] = []

    for sig in clusters:
        sig_id = sig.id()
        fp = sig.file
        cluster_start = sig.bucket.start
        cluster_end = sig.bucket.end

        row: Dict[str, Any] = {
            "signature": sig_id,
            "file": fp,
            "cluster_start": cluster_start,
            "cluster_end": cluster_end,
        }

        tools_flagging: List[str] = []
        owasp_union: set[str] = set()
        owasp_sets_nonempty: List[tuple[str, tuple[str, ...]]] = []

        for tool in tool_names:
            findings = idx_by_tool.get(tool, {}).get(sig_id) or []
            flagged = bool(findings)
            row[f"{tool}_flagged"] = flagged
            row[f"{tool}_finding_count"] = len(findings) if flagged else 0

            if not flagged:
                row[f"{tool}_rule_id"] = None
                row[f"{tool}_finding_id"] = None
                row[f"{tool}_line_number"] = None
                row[f"{tool}_end_line_number"] = None
                row[f"{tool}_cwe_id"] = None
                row[f"{tool}_cwe_ids"] = None
                row[f"{tool}_cwe_ids_union"] = []
                row[f"{tool}_severity"] = None
                row[f"{tool}_title"] = None
                row[f"{tool}_owasp_codes"] = []
                continue

            # Exemplar: first finding (simple + deterministic enough for now)
            ex = findings[0]

            # CWE aggregate (union)
            cwe_set: set[str] = set()
            for f in findings:
                if isinstance(f.get("cwe_ids"), list):
                    for c in f.get("cwe_ids") or []:
                        if isinstance(c, str) and c:
                            cwe_set.add(c)
                cwe_id = f.get("cwe_id")
                if isinstance(cwe_id, str) and cwe_id:
                    cwe_set.add(cwe_id)

            # OWASP aggregate (best-effort canonicalization)
            oset: set[str] = set()
            for f in findings:
                try:
                    codes = canonical_owasp_2021_codes(f, cwe_to_owasp_map=cwe_map)
                except Exception:
                    codes = []
                for code in codes:
                    oset.add(code)

            row[f"{tool}_rule_id"] = ex.get("rule_id")
            row[f"{tool}_finding_id"] = ex.get("finding_id")
            row[f"{tool}_line_number"] = ex.get("line_number")
            row[f"{tool}_end_line_number"] = ex.get("end_line_number")
            row[f"{tool}_cwe_id"] = ex.get("cwe_id")
            row[f"{tool}_cwe_ids"] = ex.get("cwe_ids")
            row[f"{tool}_cwe_ids_union"] = sorted(cwe_set)
            row[f"{tool}_severity"] = ex.get("severity")
            row[f"{tool}_title"] = ex.get("title")
            row[f"{tool}_owasp_codes"] = sorted(oset)

            tools_flagging.append(tool)
            owasp_union.update(oset)
            if oset:
                owasp_sets_nonempty.append((tool, tuple(sorted(oset))))

        row["tools_flagging"] = tools_flagging
        row["tools_flagging_count"] = len(tools_flagging)
        row["owasp_codes_union"] = sorted(owasp_union)

        # Taxonomy disagreement heuristic:
        # if >=2 tools have non-empty OWASP code sets and those sets differ.
        unique_code_sets = {codes for (_tool, codes) in owasp_sets_nonempty}
        row["taxonomy_disagreement"] = len(unique_code_sets) > 1

        # Optional filtering to keep CSV human-sized
        if row["tools_flagging_count"] >= max(1, int(min_tools)):
            rows.append(row)

    base_meta: Dict[str, Any] = {
        "repo": repo_name,
        "signature_type": f"(normalized_file_path, line_cluster_pm_{tolerance})",
        "tolerance": int(tolerance),
        "mode": mode,
        "tool_names": tool_names,
        "tool_inputs": tool_inputs,
        "cwe_map": str(cwe_map_path),
    }
    meta = with_standard_meta(base_meta, stage="hotspot_location_matrix", repo=repo_name, tool_names=tool_names)

    by_tools: Dict[int, int] = {}
    for r in rows:
        c = r.get("tools_flagging_count")
        if isinstance(c, int):
            by_tools[c] = by_tools.get(c, 0) + 1

    summary = {
        "rows": len(rows),
        "min_tools": int(min_tools),
        "rows_by_tools_flagging_count": dict(sorted(by_tools.items())),
    }

    return {"meta": meta, "summary": summary, "rows": rows}


def write_matrix_outputs(matrix: Dict[str, Any], out_dir: Path, name: str, formats: List[str]) -> None:
    """Write hotspot location matrix outputs (json/csv)."""
    out_dir.mkdir(parents=True, exist_ok=True)

    formats_norm = [f.strip().lower() for f in formats if f and f.strip()]

    # JSON
    if "json" in formats_norm:
        write_json(matrix, out_dir / f"{name}.json")

    # CSV
    if "csv" in formats_norm:
        rows = matrix.get("rows") or []
        if rows:
            tool_names = (matrix.get("meta") or {}).get("tool_names") or []
            base_fields = [
                "signature",
                "file",
                "cluster_start",
                "cluster_end",
                "tools_flagging_count",
                "tools_flagging",
                "taxonomy_disagreement",
                "owasp_codes_union",
            ]
            per_tool_fields: List[str] = []
            for t in tool_names:
                per_tool_fields.extend(
                    [
                        f"{t}_flagged",
                        f"{t}_finding_count",
                        f"{t}_rule_id",
                        f"{t}_finding_id",
                        f"{t}_line_number",
                        f"{t}_end_line_number",
                        f"{t}_cwe_id",
                        f"{t}_cwe_ids",
                        f"{t}_cwe_ids_union",
                        f"{t}_owasp_codes",
                        f"{t}_severity",
                        f"{t}_title",
                    ]
                )
            fieldnames = base_fields + per_tool_fields
            write_csv(rows, out_dir / f"{name}.csv", fieldnames=fieldnames)


def write_outputs(matrix: Dict[str, Any], out_dir: Path, name: str, formats: List[str]) -> None:
    """Stage-contract alias for write_matrix_outputs."""
    write_matrix_outputs(matrix, out_dir, name, formats)

def main() -> None:
    ap = argparse.ArgumentParser(description="Build a location-based hotspot matrix from a hotspot report.")
    ap.add_argument(
        "--report",
        required=True,
        help="Path to latest_hotspots_by_file.json produced by unique_overview.py",
    )
    ap.add_argument("--out-dir", required=True, help="Output directory for matrix files")
    ap.add_argument(
        "--name",
        default="latest_hotspot_location_matrix",
        help="Base name for output files (default: latest_hotspot_location_matrix)",
    )
    ap.add_argument(
        "--formats",
        default="json,csv",
        help="Comma-separated list of output formats (json,csv).",
    )
    ap.add_argument(
        "--tolerance",
        type=int,
        default=3,
        help="Line clustering tolerance (adjacent gap in lines; default: 3).",
    )
    ap.add_argument(
        "--mode",
        choices=["security", "all"],
        default="security",
        help="Finding filter mode (default: security).",
    )
    ap.add_argument(
        "--min-tools",
        type=int,
        default=1,
        help="Only include rows flagged by at least N tools (default: 1).",
    )
    ap.add_argument(
        "--cwe-map",
        default=str(REPO_ROOT_DIR / "mappings" / "cwe_to_owasp_top10_mitre.json"),
        help="Path to CWE->OWASP mapping JSON.",
    )

    args = ap.parse_args()

    report_path = Path(args.report)
    out_dir = Path(args.out_dir)
    formats = [s.strip().lower() for s in args.formats.split(",") if s.strip()]
    cwe_map_path = Path(args.cwe_map)

    matrix = build_hotspot_location_matrix(
        report_path,
        tolerance=args.tolerance,
        mode=args.mode,
        cwe_map_path=cwe_map_path,
        min_tools=args.min_tools,
    )
    write_matrix_outputs(matrix, out_dir, args.name, formats)


if __name__ == "__main__":
    main()