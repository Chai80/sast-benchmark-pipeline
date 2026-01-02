"""pipeline.analysis.tool_profile

Compute a lightweight "output quality profile" per tool.

This stage is not about *which tool is better at finding bugs*.
It is about *how usable and comparable the tool output is* once normalized.

Why this matters for benchmarks
------------------------------
When tools flag the same code location, they often differ in:

- metadata completeness (line numbers, CWEs, OWASP labels)
- labeling richness (one CWE vs many; generic CWE-20 inflation)
- severity availability

Those differences materially affect:
- triage effort
- downstream normalization
- perceived coverage in naive comparisons

Inputs
------
Typically the location matrix JSON, because it already encodes exactly which
normalized tool runs were used (meta.tool_inputs).

Outputs
-------
- tool_profile.json
- tool_profile.csv
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from pipeline.analysis.finding_filters import filter_findings
from pipeline.analysis.io_utils import as_list, load_json, write_csv, write_json
from pipeline.analysis.meta_utils import with_standard_meta


def _is_nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and bool(v.strip())


def _as_int(v: Any) -> Optional[int]:
    try:
        if v is None:
            return None
        i = int(v)
        return i
    except Exception:
        return None


def _extract_tool_inputs_from_matrix(matrix: Mapping[str, Any]) -> Dict[str, str]:
    meta = matrix.get("meta") or {}
    tool_inputs = meta.get("tool_inputs")
    if isinstance(tool_inputs, dict):
        out: Dict[str, str] = {}
        for k, v in tool_inputs.items():
            if isinstance(k, str) and isinstance(v, str) and v:
                out[k] = v
        return out
    return {}


def _extract_tool_inputs_from_report(report: Mapping[str, Any]) -> Dict[str, str]:
    tools = report.get("tools")
    if not isinstance(tools, dict):
        return {}
    out: Dict[str, str] = {}
    for tool, meta in tools.items():
        if not isinstance(tool, str) or not tool:
            continue
        if not isinstance(meta, dict):
            continue
        inp = meta.get("input")
        if isinstance(inp, str) and inp:
            out[tool] = inp
    return out


def _cwe_set(f: Mapping[str, Any]) -> set[str]:
    out: set[str] = set()
    cwe_id = f.get("cwe_id")
    if _is_nonempty_str(cwe_id):
        out.add(cwe_id.strip())
    for c in as_list(f.get("cwe_ids")):
        if _is_nonempty_str(c):
            out.add(c.strip())
    return out


def _has_owasp(f: Mapping[str, Any]) -> bool:
    # Preferred: normalized OWASP-2021 dict
    o = f.get("owasp_top_10_2021")
    if isinstance(o, dict):
        codes = o.get("codes")
        if isinstance(codes, list) and any(_is_nonempty_str(x) for x in codes):
            return True

    # Some normalizers may emit canonical codes separately
    oc = f.get("owasp_top_10_2021_canonical")
    if isinstance(oc, list) and any(_is_nonempty_str(x) for x in oc):
        return True

    return False


def build_tool_profile(*, matrix_path: Optional[Path] = None, report_path: Optional[Path] = None, mode: str = "security") -> Dict[str, Any]:
    if not matrix_path and not report_path:
        raise ValueError("Must provide either matrix_path or report_path")

    matrix: Dict[str, Any] = {}
    report: Dict[str, Any] = {}

    tool_inputs: Dict[str, str] = {}
    tool_names: List[str] = []

    if matrix_path:
        matrix = load_json(matrix_path)
        tool_inputs = _extract_tool_inputs_from_matrix(matrix)
        tool_names = list((matrix.get("meta") or {}).get("tool_names") or [])
    if report_path and not tool_inputs:
        report = load_json(report_path)
        tool_inputs = _extract_tool_inputs_from_report(report)

    if not tool_inputs:
        raise ValueError("Could not determine tool_inputs from matrix/report")

    if not tool_names:
        tool_names = sorted(tool_inputs.keys())

    rows: List[Dict[str, Any]] = []

    commits: Dict[str, Optional[str]] = {}
    scan_dates: Dict[str, Optional[str]] = {}

    for tool in tool_names:
        inp = tool_inputs.get(tool)
        if not inp:
            continue
        data = load_json(Path(inp))

        findings_raw = [f for f in as_list(data.get("findings")) if isinstance(f, dict)]
        raw_count = len(findings_raw)
        findings = filter_findings(tool, findings_raw, mode=mode)
        filtered_count = len(findings)

        # Meta (best-effort)
        tool_version = data.get("tool_version") if _is_nonempty_str(data.get("tool_version")) else None
        tr = data.get("target_repo") if isinstance(data.get("target_repo"), dict) else {}
        commit = tr.get("commit") if _is_nonempty_str(tr.get("commit")) else None
        commits[tool] = commit

        scan = data.get("scan") if isinstance(data.get("scan"), dict) else {}
        scan_date = scan.get("scan_date") if _is_nonempty_str(scan.get("scan_date")) else None
        scan_dates[tool] = scan_date

        # Completeness metrics (on filtered findings)
        with_file_path = 0
        with_line = 0
        with_end_line = 0
        with_rule_id = 0
        with_finding_id = 0
        with_severity = 0
        with_title = 0
        with_cwe = 0
        with_owasp = 0
        with_line_content = 0

        severity_counts: Dict[str, int] = {}
        unique_files: set[str] = set()

        cwe_counts_total = 0
        cwe_counts_n = 0

        for f in findings:
            fp = f.get("file_path")
            if _is_nonempty_str(fp):
                with_file_path += 1
                unique_files.add(fp.strip())

            if _as_int(f.get("line_number")) is not None:
                with_line += 1
            if _as_int(f.get("end_line_number")) is not None:
                with_end_line += 1

            if _is_nonempty_str(f.get("rule_id")):
                with_rule_id += 1
            if _is_nonempty_str(f.get("finding_id")):
                with_finding_id += 1
            if _is_nonempty_str(f.get("severity")):
                with_severity += 1
                sev = str(f.get("severity")).strip()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            if _is_nonempty_str(f.get("title")):
                with_title += 1
            if _is_nonempty_str(f.get("line_content")):
                with_line_content += 1

            cwes = _cwe_set(f)
            if cwes:
                with_cwe += 1
                cwe_counts_total += len(cwes)
                cwe_counts_n += 1

            if _has_owasp(f):
                with_owasp += 1

        def pct(x: int, denom: int) -> float:
            if denom <= 0:
                return 0.0
            return round((x / denom) * 100.0, 2)

        avg_cwes = round((cwe_counts_total / cwe_counts_n), 3) if cwe_counts_n else 0.0

        rows.append(
            {
                "tool": tool,
                "tool_version": tool_version,
                "input": inp,
                "mode": mode,
                "raw_findings": raw_count,
                "filtered_findings": filtered_count,
                "filtered_drop_pct": pct(max(0, raw_count - filtered_count), raw_count),
                "pct_with_file_path": pct(with_file_path, filtered_count),
                "pct_with_line_number": pct(with_line, filtered_count),
                "pct_with_end_line_number": pct(with_end_line, filtered_count),
                "pct_with_rule_id": pct(with_rule_id, filtered_count),
                "pct_with_finding_id": pct(with_finding_id, filtered_count),
                "pct_with_severity": pct(with_severity, filtered_count),
                "pct_with_title": pct(with_title, filtered_count),
                "pct_with_cwe": pct(with_cwe, filtered_count),
                "pct_with_owasp": pct(with_owasp, filtered_count),
                "pct_with_line_content": pct(with_line_content, filtered_count),
                "avg_cwe_per_labeled_finding": avg_cwes,
                "unique_files": len(unique_files),
                "severity_counts": severity_counts,
                "commit": commit,
                "scan_date": scan_date,
            }
        )

    # Commit consistency: all non-null commits equal
    commit_values = {c for c in commits.values() if c}
    commit_consistent = len(commit_values) <= 1
    commit_single = next(iter(commit_values)) if len(commit_values) == 1 else None

    out = {
        "meta": with_standard_meta(
            {
                "source_matrix": str(matrix_path) if matrix_path else None,
                "source_report": str(report_path) if report_path else None,
                "mode": mode,
                "tool_names": tool_names,
                "tool_inputs": tool_inputs,
            },
            stage="tool_profile",
            repo=((matrix.get("meta") or {}).get("repo") if isinstance(matrix, dict) else None),
            tool_names=tool_names,
            mode=mode,
        ),
        "summary": {
            "tools": len(rows),
            "commit_consistent": commit_consistent,
            "commit": commit_single,
            "scan_dates": scan_dates,
        },
        "rows": rows,
    }
    return out


def write_outputs(report: Dict[str, Any], out_dir: Path, name: str, formats: List[str]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    formats = [f.strip().lower() for f in formats if f.strip()]

    if "json" in formats:
        write_json(report, out_dir / f"{name}.json")

    if "csv" in formats:
        rows = report.get("rows") or []
        # Expand severity_counts as a JSON-ish string for CSV readability
        out_rows: List[Dict[str, Any]] = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            rr = dict(r)
            sc = rr.get("severity_counts")
            rr["severity_counts"] = str(sc) if sc is not None else ""
            out_rows.append(rr)
        write_csv(out_rows, out_dir / f"{name}.csv")


def main() -> None:
    ap = argparse.ArgumentParser(description="Compute per-tool output quality profiles from a location matrix.")
    ap.add_argument("--matrix", help="Path to hotspot location matrix JSON (preferred).")
    ap.add_argument("--report", help="Path to latest_hotspots_by_file.json (fallback).")
    ap.add_argument("--out-dir", required=True, help="Output directory for profile files.")
    ap.add_argument("--name", default="tool_profile", help="Base name for output files.")
    ap.add_argument("--formats", default="json,csv", help="Comma-separated output formats (json,csv).")
    ap.add_argument("--mode", choices=["security", "all"], default="security", help="Filtering mode (default: security).")

    args = ap.parse_args()
    matrix_path = Path(args.matrix) if args.matrix else None
    report_path = Path(args.report) if args.report else None

    out = build_tool_profile(matrix_path=matrix_path, report_path=report_path, mode=args.mode)
    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    write_outputs(out, Path(args.out_dir), args.name, formats)


if __name__ == "__main__":
    main()