"""pipeline.analysis.hotspot_location_matrix

Build a union-sized hotspot matrix using a *location-based* signature.

This is the next step after hotspot_matrix.py:

- hotspot_matrix.py aligns on (file, OWASP-2021) -> coarse overlap.
- hotspot_location_matrix.py aligns on (file, line_bucket) -> granular overlap.

The point is to distinguish:
- taxonomy disagreement: same code location, different labels
- detection disagreement: one tool truly doesn't raise anything at that code location
- scope/config differences: tools don't scan the same things (e.g. Sonar CODE_SMELLs)

Signature
---------
    (normalize_file_path(file_path, repo_name), line_bucket)

Where line_bucket is computed from an anchor line (line_number, else end_line_number)
and a configurable --bucket-size (default 10):

    routes/search.ts|L21-30

Outputs
-------
- JSON matrix (recommended for downstream tooling)
- CSV matrix (spreadsheet-friendly)

This script is filesystem-only; no database required.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from pipeline.analysis.location_signatures import iter_location_signatures
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


def _extract_repo_name(data: Mapping[str, Any], fallback: Optional[str]) -> Optional[str]:
    tr = data.get("target_repo")
    rn = tr.get("name") if isinstance(tr, dict) else None
    if not isinstance(rn, str) or not rn:
        return fallback
    return rn


def _filter_findings(tool: str, findings: Sequence[Mapping[str, Any]], *, mode: str) -> List[Mapping[str, Any]]:
    """Tool-aware filtering to keep location alignment meaningful.

    mode:
      - "security" (default): try to exclude obvious non-security noise
      - "all": include everything that has a location
    """

    if mode == "all":
        return list(findings)

    out: List[Mapping[str, Any]] = []
    for f in findings:
        # Sonar emits a lot of CODE_SMELLs; keep only VULNERABILITY/SECURITY_HOTSPOT by default.
        if tool == "sonar":
            t = (f.get("vendor") or {}).get("raw_result", {}).get("type")
            if t not in ("VULNERABILITY", "SECURITY_HOTSPOT"):
                continue

        # Aikido mixes SAST, secrets, open_source, iac; exclude open_source by default
        if tool == "aikido":
            t = (f.get("vendor") or {}).get("raw_result", {}).get("type")
            if t == "open_source":
                continue

        out.append(f)

    return out


def build_hotspot_location_matrix(
    report_path: Path,
    *,
    bucket_size: int = 10,
    mode: str = "security",
    cwe_map_path: Path = REPO_ROOT_DIR / "mappings" / "cwe_to_owasp_top10_mitre.json",
    min_tools: int = 1,
) -> Dict[str, Any]:
    """Build a location-based hotspot matrix from a unique_overview report."""

    report = _load_json(report_path)
    tools_meta: Dict[str, Dict[str, Any]] = report.get("tools", {})
    repo_name = report.get("repo") if isinstance(report.get("repo"), str) else None

    if not tools_meta:
        raise ValueError("Report missing 'tools' metadata. Did you pass the right JSON?")
    if bucket_size <= 0:
        raise ValueError("bucket_size must be positive")

    # Load CWE->OWASP mapping (reused for per-location taxonomy comparison)
    cwe_map: Mapping[str, Any] = _load_json(cwe_map_path)

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

        data = _load_json(Path(input_path))
        findings = [f for f in _as_list(data.get("findings")) if isinstance(f, dict)]
        findings = _filter_findings(tool, findings, mode=mode)

        findings_by_tool[tool] = findings
        repo_name_by_tool[tool] = _extract_repo_name(data, repo_name)

    # Build per-tool index: location_signature -> aggregate info
    tool_sig_info: Dict[str, Dict[str, Dict[str, Any]]] = {}
    union_keys: set[str] = set()

    for tool, findings in findings_by_tool.items():
        sig_counts: Dict[str, int] = {}
        exemplars: Dict[str, Mapping[str, Any]] = {}

        owasp_by_sig: Dict[str, set[str]] = {}
        cwes_by_sig: Dict[str, set[str]] = {}

        tool_repo_name = repo_name_by_tool.get(tool)

        for sig_id, sig, finding in iter_location_signatures(
            findings,
            repo_name=tool_repo_name,
            bucket_size=bucket_size,
        ):
            sig_counts[sig_id] = sig_counts.get(sig_id, 0) + 1
            union_keys.add(sig_id)

            if sig_id not in exemplars:
                exemplars[sig_id] = finding

            # Collect CWE ids (as-is; canonicalization happens elsewhere)
            cset = cwes_by_sig.setdefault(sig_id, set())
            if isinstance(finding.get("cwe_ids"), list):
                for c in finding.get("cwe_ids") or []:
                    if isinstance(c, str) and c:
                        cset.add(c)
            cwe_id = finding.get("cwe_id")
            if isinstance(cwe_id, str) and cwe_id:
                cset.add(cwe_id)

            # Collect canonical OWASP 2021 codes for taxonomy comparison (best-effort)
            oset = owasp_by_sig.setdefault(sig_id, set())
            try:
                codes = canonical_owasp_2021_codes(finding, cwe_to_owasp_map=cwe_map)
            except Exception:
                codes = []
            for code in codes:
                oset.add(code)

        info: Dict[str, Dict[str, Any]] = {}
        for sig_id, count in sig_counts.items():
            f = exemplars[sig_id]
            info[sig_id] = {
                "finding_count": count,
                "rule_id": f.get("rule_id"),
                "finding_id": f.get("finding_id"),
                "line_number": f.get("line_number"),
                "end_line_number": f.get("end_line_number"),
                "cwe_id": f.get("cwe_id"),
                "cwe_ids": f.get("cwe_ids"),
                "severity": f.get("severity"),
                "title": f.get("title"),
                # Aggregates (useful to detect taxonomy disagreement)
                "owasp_codes": sorted(owasp_by_sig.get(sig_id, set())),
                "cwe_ids_union": sorted(cwes_by_sig.get(sig_id, set())),
            }
        tool_sig_info[tool] = info

    # Deterministic union ordering by (file, bucket_start)
    def _union_sort_key(sig_id: str) -> tuple[str, int]:
        # sig_id format: <file>|L<start>-<end>
        try:
            fp, rest = sig_id.rsplit("|L", 1)
            start_s, _end_s = rest.split("-", 1)
            return fp, int(start_s)
        except Exception:
            return sig_id, 0

    rows: List[Dict[str, Any]] = []

    for sig_id in sorted(union_keys, key=_union_sort_key):
        # Parse file + bucket from signature id
        fp, rest = sig_id.rsplit("|L", 1)
        start_s, end_s = rest.split("-", 1)
        bucket_start = int(start_s)
        bucket_end = int(end_s)

        row: Dict[str, Any] = {
            "signature": sig_id,
            "file": fp,
            "bucket_start": bucket_start,
            "bucket_end": bucket_end,
        }

        tools_flagging: List[str] = []
        owasp_union: set[str] = set()
        owasp_sets_nonempty: List[tuple[str, tuple[str, ...]]] = []

        for tool in tool_names:
            cell = tool_sig_info.get(tool, {}).get(sig_id)
            flagged = cell is not None
            row[f"{tool}_flagged"] = flagged
            row[f"{tool}_finding_count"] = cell["finding_count"] if flagged else 0
            row[f"{tool}_rule_id"] = cell["rule_id"] if flagged else None
            row[f"{tool}_finding_id"] = cell["finding_id"] if flagged else None
            row[f"{tool}_line_number"] = cell["line_number"] if flagged else None
            row[f"{tool}_end_line_number"] = cell["end_line_number"] if flagged else None
            row[f"{tool}_cwe_id"] = cell["cwe_id"] if flagged else None
            row[f"{tool}_cwe_ids"] = cell["cwe_ids"] if flagged else None
            row[f"{tool}_cwe_ids_union"] = cell["cwe_ids_union"] if flagged else []
            row[f"{tool}_severity"] = cell["severity"] if flagged else None
            row[f"{tool}_title"] = cell["title"] if flagged else None
            row[f"{tool}_owasp_codes"] = cell["owasp_codes"] if flagged else []

            if flagged:
                tools_flagging.append(tool)
                for c in cell.get("owasp_codes") or []:
                    owasp_union.add(c)
                codes = tuple(sorted(cell.get("owasp_codes") or []))
                if codes:
                    owasp_sets_nonempty.append((tool, codes))

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

    meta: Dict[str, Any] = {
        "repo": repo_name,
        "signature_type": f"(normalized_file_path, line_bucket_{bucket_size})",
        "bucket_size": bucket_size,
        "mode": mode,
        "tool_names": tool_names,
        "tool_inputs": tool_inputs,
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
            tool_names = (matrix.get("meta") or {}).get("tool_names") or []
            base_fields = [
                "signature",
                "file",
                "bucket_start",
                "bucket_end",
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

            with (out_dir / f"{name}.csv").open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)


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
        "--bucket-size",
        type=int,
        default=10,
        help="Line bucket size (default: 10).",
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
        bucket_size=args.bucket_size,
        mode=args.mode,
        cwe_map_path=cwe_map_path,
        min_tools=args.min_tools,
    )
    write_matrix_outputs(matrix, out_dir, args.name, formats)


if __name__ == "__main__":
    main()
