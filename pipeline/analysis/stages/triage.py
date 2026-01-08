from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json
from pipeline.analysis.utils.signatures import cluster_locations

from ._shared import build_location_items, max_severity, severity_rank


def _sample_field(items: List[Dict[str, Any]], field: str) -> str:
    for it in items or []:
        v = it.get(field)
        if v:
            return str(v)
    return ""


@register_stage(
    "triage_queue",
    kind="analysis",
    description="Create a ranked triage queue of hotspots to review first.",
)
def stage_triage(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    clusters = store.get("location_clusters")
    if not isinstance(clusters, list):
        items = build_location_items(ctx, store)
        clusters = cluster_locations(items, tolerance=ctx.tolerance, repo_name=ctx.repo_name)
        store.put("location_clusters", clusters)

    rows: List[Dict[str, Any]] = []
    for c in clusters:
        items = list(c.get("items") or [])
        tool_counts = Counter()
        for it in items:
            tool_counts[str(it.get("tool") or "")] += 1

        sev, sev_rank = max_severity(items)
        title = _sample_field(items, "title")
        rule_id = _sample_field(items, "rule_id")

        rows.append(
            {
                "file_path": c.get("file_path"),
                "start_line": c.get("start_line"),
                "end_line": c.get("end_line"),
                "tools": ",".join(c.get("tools") or []),
                "tool_count": int(c.get("tool_count") or 0),
                "total_findings": int(sum(tool_counts.values())),
                "max_severity": sev,
                "sample_rule_id": rule_id,
                "sample_title": title,
                "cluster_id": c.get("cluster_id"),
                "_sev_rank": sev_rank,
            }
        )

    # Rank triage: most tools agree, then severity, then most findings.
    rows.sort(
        key=lambda r: (
            -int(r.get("tool_count", 0)),
            -int(r.get("_sev_rank", 0)),
            -int(r.get("total_findings", 0)),
            str(r.get("file_path") or ""),
            int(r.get("start_line") or 0),
        )
    )
    for i, r in enumerate(rows, start=1):
        r["rank"] = i
        r.pop("_sev_rank", None)

    store.put("triage_rows", rows)

    out_csv = Path(ctx.out_dir) / "triage_queue.csv"
    out_json = Path(ctx.out_dir) / "triage_queue.json"
    if "csv" in ctx.formats:
        write_csv(
            out_csv,
            rows,
            fieldnames=[
                "rank",
                "file_path",
                "start_line",
                "end_line",
                "tool_count",
                "tools",
                "total_findings",
                "max_severity",
                "sample_rule_id",
                "sample_title",
                "cluster_id",
            ],
        )
        store.add_artifact("triage_queue_csv", out_csv)
    if "json" in ctx.formats:
        write_json(out_json, rows)
        store.add_artifact("triage_queue_json", out_json)

    return {"rows": len(rows), "top_tool_count": int(rows[0]["tool_count"]) if rows else 0}


def main(argv: List[str] | None = None) -> None:  # pragma: no cover
    ap = argparse.ArgumentParser(description="Generate triage queue (wrapper around analysis suite).")
    ap.add_argument("--repo-name", required=True)
    ap.add_argument("--runs-dir", default="runs")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--tools", default="semgrep,snyk,sonar,aikido")
    ap.add_argument("--tolerance", type=int, default=3)
    ap.add_argument("--mode", choices=["security", "all"], default="security")
    args = ap.parse_args(argv)

    from pipeline.analysis.runner import run_suite

    tools = [t.strip() for t in str(args.tools).split(",") if t.strip()]
    out_dir = Path(args.out_dir) if args.out_dir else (Path(args.runs_dir) / "analysis" / args.repo_name)
    run_suite(
        repo_name=args.repo_name,
        tools=tools,
        runs_dir=Path(args.runs_dir),
        out_dir=out_dir,
        tolerance=args.tolerance,
        mode=args.mode,
        formats=["json", "csv"],
    )
