"""pipeline.analysis.hotspot_matrix

Build a union-sized hotspot matrix from `latest_hotspots_by_file.json`.

This is an *investigation spreadsheet* generator:
- rows = signatures from the report union (file|OWASP-2021)
- columns = per-tool boolean + exemplar metadata (rule/id/line/CWE/severity/title)

Matrix correctness requirement
------------------------------
The matrix MUST use the *exact same signature construction logic* as
`pipeline.analysis.unique_overview`, otherwise you can end up with impossible
rows: a union signature that is flagged by zero tools.

In this pipeline, the signature is:
  (normalize_file_path(file_path, repo_name), canonical_owasp_2021_code)

Where canonical_owasp_2021_code is resolved by:
  1) `owasp_top_10_2021_canonical.codes` if present, else
  2) deriving from CWE(s) using the shared MITRE mapping.
"""

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from pipeline.analysis.path_normalization import normalize_file_path
from pipeline.analysis.unique_overview import canonical_owasp_2021_codes
from pipeline.core import ROOT_DIR as REPO_ROOT_DIR


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object at {path}")
    return data


def _as_list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


def build_hotspot_matrix(
    report_path: Path,
    *,
    cwe_map_path: Path = REPO_ROOT_DIR / "mappings" / "cwe_to_owasp_top10_mitre.json",
) -> Dict[str, Any]:
    """Build a union-sized hotspot matrix from latest_hotspots_by_file.json.

    Each row is a hotspot signature (file|OWASP) and carries per-tool exemplar info.

    IMPORTANT: This recomputes tool signatures using the same logic as unique_overview,
    so it stays consistent with report['union_signatures'].
    """

    report = _load_json(report_path)

    tools_meta: Dict[str, Dict[str, Any]] = report.get("tools", {})
    signature_type = report.get("signature_type")
    repo_name = report.get("repo") if isinstance(report.get("repo"), str) else None

    # unique_overview now emits union_signatures, but keep backward-compat:
    # if missing, we'll compute it after we build per-tool signatures below.
    union = report.get("union_signatures") if isinstance(report.get("union_signatures"), list) else None

    # Load CWE->OWASP mapping (same one unique_overview uses for canonicalization)
    cwe_map: Mapping[str, Any] = _load_json(cwe_map_path)

    # Load normalized findings + repo name per tool
    findings_by_tool: Dict[str, List[Dict[str, Any]]] = {}
    repo_name_by_tool: Dict[str, Optional[str]] = {}

    for tool, meta in tools_meta.items():
        input_path = meta.get("input")
        if not isinstance(input_path, str) or not input_path:
            raise ValueError(f"Tool '{tool}' missing tools[tool].input in report.")
        data = _load_json(Path(input_path))

        findings_by_tool[tool] = [f for f in _as_list(data.get("findings")) if isinstance(f, dict)]

        # Prefer target_repo.name from normalized JSON; fall back to report repo name
        tr = data.get("target_repo")
        rn = tr.get("name") if isinstance(tr, dict) else None
        if not isinstance(rn, str) or not rn:
            rn = repo_name
        repo_name_by_tool[tool] = rn

    # For each tool, build: signature -> exemplar + count
    tool_sig_info: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for tool, findings in findings_by_tool.items():
        sig_counts: Dict[str, int] = {}
        exemplars: Dict[str, Dict[str, Any]] = {}

        tool_repo_name = repo_name_by_tool.get(tool)

        for finding in findings:
            raw_fp = finding.get("file_path")
            if raw_fp is None:
                continue
            fp = normalize_file_path(str(raw_fp), tool_repo_name)
            if not fp:
                continue

            # Use the SAME OWASP-code resolution as unique_overview
            codes = canonical_owasp_2021_codes(finding, cwe_to_owasp_map=cwe_map)
            if not codes:
                continue

            for code in codes:
                sig_str = f"{fp}|{code}"
                sig_counts[sig_str] = sig_counts.get(sig_str, 0) + 1
                # Use first-seen finding as exemplar (deterministic within one JSON file)
                if sig_str not in exemplars:
                    exemplars[sig_str] = finding

        info: Dict[str, Dict[str, Any]] = {}
        for sig_str, count in sig_counts.items():
            f = exemplars[sig_str]
            info[sig_str] = {
                "finding_count": count,
                "rule_id": f.get("rule_id"),
                "finding_id": f.get("finding_id"),
                "line_number": f.get("line_number"),
                "cwe_id": f.get("cwe_id"),
                "cwe_ids": f.get("cwe_ids"),
                "severity": f.get("severity"),
                "title": f.get("title"),
            }
        tool_sig_info[tool] = info

    # Backwards-compat: if the report didn't include union_signatures, compute it
    # from the per-tool signature maps we just built (same signature logic).
    if union is None:
        union_keys: set[str] = set()
        for info in tool_sig_info.values():
            union_keys.update(info.keys())

        # Deterministic ordering: sort by (file_path, owasp_code)
        def _sig_sort_key(sig_str: str) -> tuple[str, str]:
            fp, code = sig_str.rsplit("|", 1)
            return fp, code

        union = []
        for sig_str in sorted(union_keys, key=_sig_sort_key):
            fp, code = sig_str.rsplit("|", 1)
            union.append({"signature": sig_str, "file": fp, "code": code})

    # Build matrix rows
    rows: List[Dict[str, Any]] = []
    tool_names = sorted(tools_meta.keys())

    for entry in union:
        sig_str = entry["signature"]
        row: Dict[str, Any] = {
            "signature": sig_str,
            "file": entry["file"],
            "owasp_code": entry["code"],
        }

        tools_flagging: List[str] = []
        for tool in tool_names:
            cell = tool_sig_info.get(tool, {}).get(sig_str)
            flagged = cell is not None
            row[f"{tool}_flagged"] = flagged
            row[f"{tool}_finding_count"] = cell["finding_count"] if flagged else 0
            row[f"{tool}_rule_id"] = cell["rule_id"] if flagged else None
            row[f"{tool}_finding_id"] = cell["finding_id"] if flagged else None
            row[f"{tool}_line_number"] = cell["line_number"] if flagged else None
            row[f"{tool}_cwe_id"] = cell["cwe_id"] if flagged else None
            row[f"{tool}_cwe_ids"] = cell["cwe_ids"] if flagged else None
            row[f"{tool}_severity"] = cell["severity"] if flagged else None
            row[f"{tool}_title"] = cell["title"] if flagged else None

            if flagged:
                tools_flagging.append(tool)

        row["tools_flagging"] = tools_flagging
        row["tools_flagging_count"] = len(tools_flagging)
        rows.append(row)

    # Hard correctness check: every union signature must be flagged by >=1 tool.
    zero = [r["signature"] for r in rows if r.get("tools_flagging_count", 0) == 0]
    if zero:
        raise ValueError(
            "Matrix correctness failure: found union signatures flagged by zero tools. "
            "This indicates signature mismatch between report + matrix generation. "
            f"Examples: {zero[:10]}"
        )

    meta: Dict[str, Any] = {
        "repo": repo_name,
        "signature_type": signature_type,
        "tool_names": tool_names,
        "cwe_map": str(cwe_map_path),
    }
    return {"meta": meta, "rows": rows}


def write_matrix_outputs(matrix: Dict[str, Any], out_dir: Path, name: str, formats: List[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # JSON
    if "json" in formats:
        with (out_dir / f"{name}.json").open("w", encoding="utf-8") as f:
            json.dump(matrix, f, indent=2)

    # CSV
    if "csv" in formats:
        rows = matrix.get("rows") or []
        if rows:
            # Stable column order (prevents columns from "jumping" between runs)
            tool_names = (matrix.get("meta") or {}).get("tool_names") or []
            base_fields = ["signature", "file", "owasp_code", "tools_flagging_count", "tools_flagging"]
            per_tool_fields = []
            for t in tool_names:
                per_tool_fields.extend(
                    [
                        f"{t}_flagged",
                        f"{t}_finding_count",
                        f"{t}_rule_id",
                        f"{t}_finding_id",
                        f"{t}_line_number",
                        f"{t}_cwe_id",
                        f"{t}_cwe_ids",
                        f"{t}_severity",
                        f"{t}_title",
                    ]
                )
            fieldnames = base_fields + per_tool_fields
            with (out_dir / f"{name}.csv").open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)


def main() -> None:
    ap = argparse.ArgumentParser(description="Build hotspot matrix from hotspot summary report.")
    ap.add_argument(
        "--report",
        required=True,
        help="Path to latest_hotspots_by_file.json produced by unique_overview.py",
    )
    ap.add_argument(
        "--out-dir",
        required=True,
        help="Output directory for matrix files",
    )
    ap.add_argument(
        "--name",
        default="latest_hotspot_matrix",
        help="Base name for output files (default: latest_hotspot_matrix)",
    )
    ap.add_argument(
        "--formats",
        default="json,csv",
        help="Comma-separated list of output formats (json,csv).",
    )
    ap.add_argument(
        "--cwe-map",
        default=str(REPO_ROOT_DIR / "mappings" / "cwe_to_owasp_top10_mitre.json"),
        help="Path to CWE->OWASP mapping JSON (must match unique_overview).",
    )

    args = ap.parse_args()

    report_path = Path(args.report)
    out_dir = Path(args.out_dir)
    formats = [s.strip().lower() for s in args.formats.split(",") if s.strip()]
    cwe_map_path = Path(args.cwe_map)

    matrix = build_hotspot_matrix(report_path, cwe_map_path=cwe_map_path)
    write_matrix_outputs(matrix, out_dir, args.name, formats)


if __name__ == "__main__":
    main()
