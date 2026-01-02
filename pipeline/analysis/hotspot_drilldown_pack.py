"""pipeline.analysis.hotspot_drilldown_pack

Export a lightweight per-hotspot evidence pack for *location* hotspots.

This is designed to support manual review / adjudication without a database.

Inputs
------
- A unique_overview report JSON (to locate per-tool normalized JSONs)
- A hotspot_location_matrix JSON (to get the selected hotspot rows + meta)
- A local repo checkout (to export code context)

Outputs
-------
A directory tree like:

  drilldowns/<repo>/<pack_name>/
    manifest.json
    <hotspot_dir>/
      row.json
      code_context.txt
      tools/
        sonar/findings.json
        semgrep/findings.json
        ...

Selection
---------
Provide signatures explicitly via --signatures or --signatures-file, OR use
--min-tools to export all rows with >= N tools flagging.

No database, no UI, filesystem artifacts only.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from pipeline.analysis.location_signatures import build_location_cluster_index, safe_dir_name
from pipeline.core import ROOT_DIR as REPO_ROOT_DIR


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object at {path}")
    return data


def _as_list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


def _extract_repo_name_from_report(report: Mapping[str, Any]) -> str:
    rn = report.get("repo")
    return rn if isinstance(rn, str) and rn else "unknown"


def _filter_findings(tool: str, findings: Sequence[Mapping[str, Any]], *, mode: str) -> List[Mapping[str, Any]]:
    """Keep filtering logic consistent with hotspot_location_matrix."""
    if mode == "all":
        return list(findings)

    out: List[Mapping[str, Any]] = []
    for f in findings:
        if tool == "sonar":
            t = (f.get("vendor") or {}).get("raw_result", {}).get("type")
            if t not in ("VULNERABILITY", "SECURITY_HOTSPOT"):
                continue
        if tool == "aikido":
            t = (f.get("vendor") or {}).get("raw_result", {}).get("type")
            if t == "open_source":
                continue
        out.append(f)
    return out


def _read_file_context(
    repo_path: Path,
    rel_file: str,
    *,
    start_line: int,
    end_line: int,
    context: int = 20,
) -> str:
    """Read a window of code around a [start_line, end_line] span."""
    fp = repo_path / rel_file
    try:
        text = fp.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return f"[missing file] {rel_file}\n"
    lines = text.splitlines()
    if not lines:
        return f"[empty file] {rel_file}\n"

    # Clamp to file bounds (1-indexed line numbers)
    lo = max(1, int(start_line) - int(context))
    hi = min(len(lines), int(end_line) + int(context))

    out_lines: List[str] = []
    out_lines.append(f"FILE: {rel_file}")
    out_lines.append(f"SPAN: L{start_line}-{end_line} (context ±{context})")
    out_lines.append("")

    for i in range(lo, hi + 1):
        prefix = ">" if start_line <= i <= end_line else " "
        out_lines.append(f"{prefix}{i:>6} | {lines[i-1]}")
    out_lines.append("")

    return "\n".join(out_lines)


def _parse_signature_list(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    items = [s.strip() for s in raw.split(",") if s.strip()]
    # Deduplicate while preserving order
    seen = set()
    out: List[str] = []
    for s in items:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def build_pack(
    *,
    report_path: Path,
    matrix_path: Path,
    repo_path: Path,
    out_dir: Path,
    pack_name: str,
    signatures: Sequence[str],
    signatures_file: Optional[Path],
    min_tools: Optional[int],
    context: int,
) -> Path:
    report = _load_json(report_path)
    matrix = _load_json(matrix_path)

    meta = matrix.get("meta") if isinstance(matrix.get("meta"), dict) else {}
    tolerance = meta.get("tolerance") if isinstance(meta.get("tolerance"), int) else None
    mode = meta.get("mode") if isinstance(meta.get("mode"), str) else "security"
    tool_names = meta.get("tool_names") if isinstance(meta.get("tool_names"), list) else []

    if tolerance is None:
        raise ValueError("Matrix meta.tolerance missing; is this a location matrix JSON?")
    if not tool_names:
        raise ValueError("Matrix meta.tool_names missing; is this a location matrix JSON?")

    tools_meta = report.get("tools") if isinstance(report.get("tools"), dict) else {}
    if not tools_meta:
        raise ValueError("Report missing tools metadata; pass the unique_overview report JSON")

    # Load normalized findings per tool using report paths (keeps drilldown tied to the same run set)
    findings_by_tool: Dict[str, List[Mapping[str, Any]]] = {}
    repo_name_by_tool: Dict[str, Optional[str]] = {}

    for tool in tool_names:
        tmeta = tools_meta.get(tool) or {}
        input_path = tmeta.get("input")
        if not isinstance(input_path, str) or not input_path:
            # Tool missing from report; still include empty bucket
            findings_by_tool[tool] = []
            repo_name_by_tool[tool] = None
            continue

        data = _load_json(Path(input_path))
        findings = [f for f in _as_list(data.get("findings")) if isinstance(f, dict)]
        findings = _filter_findings(tool, findings, mode=mode)
        findings_by_tool[tool] = findings

        tr = data.get("target_repo")
        rn = tr.get("name") if isinstance(tr, dict) else None
        repo_name_by_tool[tool] = rn if isinstance(rn, str) and rn else _extract_repo_name_from_report(report)

    # Build canonical clusters across tools (must match hotspot_location_matrix)
    _clusters, idx_by_tool = build_location_cluster_index(
        findings_by_tool=findings_by_tool,
        repo_name_by_tool=repo_name_by_tool,
        tolerance=int(tolerance),
    )

    # Load matrix rows and select rows
    rows = matrix.get("rows")
    if not isinstance(rows, list):
        raise ValueError("Matrix missing rows list")

    selected_sigs: List[str] = list(signatures)

    if signatures_file:
        for line in signatures_file.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s and not s.startswith("#") and s not in selected_sigs:
                selected_sigs.append(s)

    if not selected_sigs:
        # Selection by min-tools
        mt = int(min_tools or 1)
        for r in rows:
            if not isinstance(r, dict):
                continue
            if int(r.get("tools_flagging_count") or 0) >= mt:
                sig = r.get("signature")
                if isinstance(sig, str) and sig:
                    selected_sigs.append(sig)

    selected_set = set(selected_sigs)

    selected_rows: List[Mapping[str, Any]] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        sig = r.get("signature")
        if isinstance(sig, str) and sig in selected_set:
            selected_rows.append(r)

    repo_name = _extract_repo_name_from_report(report)

    pack_root = out_dir / repo_name / pack_name
    pack_root.mkdir(parents=True, exist_ok=True)

    manifest: Dict[str, Any] = {
        "repo": repo_name,
        "pack_name": pack_name,
        "matrix": str(matrix_path),
        "report": str(report_path),
        "repo_path": str(repo_path),
        "tolerance": tolerance,
        "mode": mode,
        "tool_names": tool_names,
        "selected_signatures": list(selected_sigs),
        "selected_rows": len(selected_rows),
    }

    (pack_root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    for r in selected_rows:
        sig_id = r.get("signature")
        if not isinstance(sig_id, str) or not sig_id:
            continue

        # Parse bucket from signature id: <file>|L<start>-<end>
        try:
            fp, rest = sig_id.rsplit("|L", 1)
            start_s, end_s = rest.split("-", 1)
            bucket_start = int(start_s)
            bucket_end = int(end_s)
        except Exception:
            fp = str(r.get("file") or "")
            bucket_start = int(r.get("cluster_start") or r.get("bucket_start") or 1)
            bucket_end = int(r.get("cluster_end") or r.get("bucket_end") or bucket_start)

        hotspot_dir = pack_root / safe_dir_name(sig_id)
        hotspot_dir.mkdir(parents=True, exist_ok=True)

        # Row snapshot
        (hotspot_dir / "row.json").write_text(json.dumps(r, indent=2), encoding="utf-8")

        # Code context
        ctx = _read_file_context(repo_path, fp, start_line=bucket_start, end_line=bucket_end, context=context)
        (hotspot_dir / "code_context.txt").write_text(ctx, encoding="utf-8")

        tools_dir = hotspot_dir / "tools"
        tools_dir.mkdir(exist_ok=True)

        for tool in tool_names:
            tdir = tools_dir / tool
            tdir.mkdir(exist_ok=True)
            findings = idx_by_tool.get(tool, {}).get(sig_id) or []
            (tdir / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")

    return pack_root


def main() -> None:
    ap = argparse.ArgumentParser(description="Export a drilldown evidence pack for selected location hotspots.")
    ap.add_argument("--report", required=True, help="Path to unique_overview report JSON (latest_hotspots_by_file.json)")
    ap.add_argument("--matrix", required=True, help="Path to hotspot_location_matrix JSON")
    ap.add_argument("--repo-path", required=True, help="Path to local repo checkout (for code context)")
    ap.add_argument("--out-dir", required=True, help="Base output directory for drilldown packs")
    ap.add_argument("--pack-name", default="drilldown_pack", help="Pack folder name (default: drilldown_pack)")
    ap.add_argument("--signatures", help="Comma-separated list of signature ids to export")
    ap.add_argument("--signatures-file", type=str, help="Text file containing signature ids (one per line)")
    ap.add_argument("--min-tools", type=int, help="If no signatures provided, export all rows flagged by >= N tools")
    ap.add_argument("--context", type=int, default=20, help="Context lines around the bucket span (default: 20)")

    args = ap.parse_args()

    out = build_pack(
        report_path=Path(args.report),
        matrix_path=Path(args.matrix),
        repo_path=Path(args.repo_path),
        out_dir=Path(args.out_dir),
        pack_name=str(args.pack_name),
        signatures=_parse_signature_list(args.signatures),
        signatures_file=Path(args.signatures_file) if args.signatures_file else None,
        min_tools=args.min_tools,
        context=int(args.context),
    )

    print(str(out))


if __name__ == "__main__":
    main()
