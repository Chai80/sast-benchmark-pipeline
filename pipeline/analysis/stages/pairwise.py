from __future__ import annotations

from pipeline.scanners import DEFAULT_SCANNERS_CSV

import argparse
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, List

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json

from .common.locations import ensure_location_clusters
from .common.store_keys import StoreKeys

@register_stage(
    "pairwise_agreement",
    kind="analysis",
    description="Compute pairwise Jaccard similarity across tools over clustered locations.",
)
def stage_pairwise(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    clusters = ensure_location_clusters(ctx, store)

    tool_to_clusters: Dict[str, set[str]] = {t: set() for t in ctx.tools}
    for c in clusters:
        cid = str(c.get("cluster_id") or "")
        for t in c.get("tools") or []:
            if t in tool_to_clusters:
                tool_to_clusters[t].add(cid)

    rows: List[Dict[str, Any]] = []
    for a, b in combinations(list(ctx.tools), 2):
        sa = tool_to_clusters.get(a) or set()
        sb = tool_to_clusters.get(b) or set()
        inter = len(sa & sb)
        union = len(sa | sb)
        j = (inter / union) if union else 0.0
        rows.append(
            {
                "tool_a": a,
                "tool_b": b,
                "clusters_a": len(sa),
                "clusters_b": len(sb),
                "intersection": inter,
                "union": union,
                "jaccard": round(j, 6),
            }
        )

    store.put(StoreKeys.PAIRWISE_ROWS, rows)

    out_csv = Path(ctx.out_dir) / "pairwise_agreement.csv"
    out_json = Path(ctx.out_dir) / "pairwise_agreement.json"

    if "csv" in ctx.formats:
        write_csv(out_csv, rows, fieldnames=["tool_a", "tool_b", "clusters_a", "clusters_b", "intersection", "union", "jaccard"])
        store.add_artifact("pairwise_agreement_csv", out_csv)
    if "json" in ctx.formats:
        write_json(out_json, rows)
        store.add_artifact("pairwise_agreement_json", out_json)

    return {"pairs": len(rows)}


def main(argv: List[str] | None = None) -> None:  # pragma: no cover
    ap = argparse.ArgumentParser(description="Compute pairwise agreement (wrapper around analysis suite).")
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
