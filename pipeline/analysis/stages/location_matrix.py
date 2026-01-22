from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json
from pipeline.analysis.utils.signatures import cluster_locations

from pipeline.scanners import DEFAULT_SCANNERS_CSV

from .common.locations import build_location_items
from .common.severity import max_severity
from .common.store_keys import StoreKeys


@register_stage(
    "location_matrix",
    kind="analysis",
    description="Cluster findings into location buckets and write a per-location tool matrix.",
)
def stage_location_matrix(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    items = build_location_items(ctx, store)
    clusters = cluster_locations(items, tolerance=ctx.tolerance, repo_name=ctx.repo_name)
    store.put(StoreKeys.LOCATION_CLUSTERS, clusters)

    tools = list(ctx.tools)

    rows: List[Dict[str, Any]] = []
    for c in clusters:
        tool_counts = Counter()
        for it in c.get("items") or []:
            tool_counts[str(it.get("tool") or "")] += 1

        sev, _rank = max_severity(list(c.get("items") or []))
        rows.append(
            {
                "cluster_id": c.get("cluster_id"),
                "file_path": c.get("file_path"),
                "start_line": c.get("start_line"),
                "end_line": c.get("end_line"),
                "tool_count": c.get("tool_count"),
                "tools": ",".join(c.get("tools") or []),
                "total_findings": sum(tool_counts.values()),
                "max_severity": sev,
                **{f"{t}_count": int(tool_counts.get(t, 0)) for t in tools},
            }
        )

    store.put(StoreKeys.LOCATION_MATRIX_ROWS, rows)

    out_json = Path(ctx.out_dir) / "location_matrix.json"
    out_csv = Path(ctx.out_dir) / "location_matrix.csv"

    if "json" in ctx.formats:
        write_json(out_json, rows)
        store.add_artifact("location_matrix_json", out_json)
    if "csv" in ctx.formats:
        fieldnames = [
            "cluster_id",
            "file_path",
            "start_line",
            "end_line",
            "tool_count",
            "tools",
            "total_findings",
            "max_severity",
        ] + [f"{t}_count" for t in tools]
        write_csv(out_csv, rows, fieldnames=fieldnames)
        store.add_artifact("location_matrix_csv", out_csv)

    return {"clusters": len(rows)}


def main(argv: List[str] | None = None) -> None:  # pragma: no cover
    ap = argparse.ArgumentParser(description="Generate a location matrix from normalized findings.")
    ap.add_argument("--repo-name", required=True)
    ap.add_argument("--runs-dir", default="runs")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--tools", default=DEFAULT_SCANNERS_CSV)
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
