from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Sequence

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.discovery import find_latest_normalized_json
from pipeline.analysis.io.write_artifacts import write_json
from pipeline.analysis.utils.filters import filter_findings
from pipeline.analysis.utils.path_norm import is_excluded_path, normalize_file_path

from pipeline.scanners import DEFAULT_SCANNERS_CSV

from .common.findings import load_normalized_json
from .common.store_keys import StoreKeys


def analyze_latest_hotspots_for_repo(
    *,
    repo_name: str,
    tools: Sequence[str],
    runs_dir: Path,
    mode: str = "security",
    exclude_prefixes: Sequence[str] | None = None,
) -> Dict[str, Any]:
    """Compute a simple per-file overlap report from the latest normalized run for each tool."""
    runs_dir = Path(runs_dir)

    file_to_tool_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    tool_to_files: Dict[str, set[str]] = defaultdict(set)
    tool_to_findings_count: Dict[str, int] = defaultdict(int)

    used_tools: List[str] = []

    exclude_prefixes = tuple([str(p).strip() for p in (exclude_prefixes or ()) if str(p).strip()])

    for tool in tools:
        try:
            norm_path = find_latest_normalized_json(runs_dir=runs_dir, tool=tool, repo_name=repo_name)
        except FileNotFoundError:
            continue
        data = load_normalized_json(norm_path)
        findings = data.get("findings") or []
        if not isinstance(findings, list):
            findings = []
        findings = filter_findings(tool, findings, mode=mode)

        used_tools.append(tool)
        tool_to_findings_count[tool] = len(findings)

        for f in findings:
            if not isinstance(f, dict):
                continue
            fp = normalize_file_path(str(f.get("file_path") or ""), repo_name=repo_name)
            if not fp:
                continue
            if exclude_prefixes and is_excluded_path(
                fp,
                repo_name=repo_name,
                exclude_prefixes=exclude_prefixes,
            ):
                continue

            tool_to_files[tool].add(fp)
            file_to_tool_counts[fp][tool] += 1

    files: List[Dict[str, Any]] = []
    for fp, counts in file_to_tool_counts.items():
        tools_here = sorted([t for t, c in counts.items() if c > 0])
        files.append(
            {
                "file_path": fp,
                "tools": tools_here,
                "tool_count": len(tools_here),
                "finding_counts": {t: int(counts.get(t, 0)) for t in tools_here},
            }
        )

    files.sort(key=lambda r: (-int(r.get("tool_count", 0)), str(r.get("file_path"))))

    by_tool: Dict[str, Any] = {}
    for tool in used_tools:
        files_for_tool = sorted(tool_to_files.get(tool) or [])
        unique_files = [fp for fp in files_for_tool if (file_to_tool_counts.get(fp) and len(file_to_tool_counts[fp]) == 1)]
        by_tool[tool] = {
            "findings": int(tool_to_findings_count.get(tool, 0)),
            "files": len(files_for_tool),
            "unique_files": len(unique_files),
            "unique_files_list": unique_files,
        }

    return {
        "repo_name": repo_name,
        "mode": mode,
        "exclude_prefixes": list(exclude_prefixes),
        "tools": used_tools,
        "by_tool": by_tool,
        "files": files,
    }


def print_text_report(report: Dict[str, Any], *, max_unique: int = 25) -> None:
    """Human-friendly text report for hotspots-by-file."""
    tools = report.get("tools") or []
    print(f"Repo: {report.get('repo_name')}")
    print(f"Mode: {report.get('mode')}")

    ex = report.get("exclude_prefixes") or []
    if ex:
        print("Exclude prefixes:", ", ".join([str(p) for p in ex]))

    print("Tools:", ", ".join(tools))
    print()

    by_tool = report.get("by_tool") or {}
    for tool in tools:
        t = by_tool.get(tool) or {}
        print(f"== {tool} ==")
        print(f"Findings: {t.get('findings', 0)}")
        print(f"Files hit: {t.get('files', 0)}")
        print(f"Unique files: {t.get('unique_files', 0)}")
        uniq = (t.get("unique_files_list") or [])[: int(max_unique)]
        if uniq:
            print("Top unique files:")
            for fp in uniq:
                print("  -", fp)
        print()


@register_stage(
    "overview",
    kind="analysis",
    description="Compute per-file overlap + unique-file summary across tools.",
)
def stage_overview(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    report = analyze_latest_hotspots_for_repo(
        repo_name=ctx.repo_name,
        tools=ctx.tools,
        runs_dir=ctx.runs_dir,
        mode=ctx.mode,
        exclude_prefixes=getattr(ctx, "exclude_prefixes", ()) or (),
    )
    store.put(StoreKeys.OVERVIEW_REPORT, report)

    out_path = Path(ctx.out_dir) / "latest_hotspots_by_file.json"
    write_json(out_path, report)
    store.add_artifact("latest_hotspots_by_file", out_path)

    return {
        "tools": report.get("tools") or [],
        "files": len(report.get("files") or []),
    }


def main(argv: List[str] | None = None) -> None:  # pragma: no cover
    ap = argparse.ArgumentParser(description="Compute latest hotspots-by-file overlap report.")
    ap.add_argument("--repo-name", required=True)
    ap.add_argument("--runs-dir", default="runs")
    ap.add_argument("--tools", default=DEFAULT_SCANNERS_CSV)
    ap.add_argument("--mode", choices=["security", "all"], default="security")
    ap.add_argument("--exclude-prefix", action="append", default=[], help="Repeatable repo-relative prefix to exclude")
    ap.add_argument("--out", help="Optional output JSON path")
    ap.add_argument("--max-unique", type=int, default=25)
    args = ap.parse_args(argv)

    tools = [t.strip() for t in str(args.tools).split(",") if t.strip()]
    report = analyze_latest_hotspots_for_repo(
        repo_name=args.repo_name,
        tools=tools,
        runs_dir=Path(args.runs_dir),
        mode=args.mode,
        exclude_prefixes=args.exclude_prefix,
    )

    if args.out:
        write_json(Path(args.out), report)
    else:
        print_text_report(report, max_unique=args.max_unique)
