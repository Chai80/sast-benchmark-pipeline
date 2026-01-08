from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_json


def build_benchmark_pack(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    """Build a single JSON object suitable for DB ingestion later."""
    overview = store.get("overview_report") or {}
    tool_profile = store.get("tool_profile_rows") or []
    pairwise = store.get("pairwise_rows") or []
    taxonomy = store.get("taxonomy_rows") or []
    triage = store.get("triage_rows") or []

    # Keep pack relatively small: include top-N triage rows.
    triage_top = list(triage)[:200]

    pack = {
        "schema_version": "benchmark_pack_v1",
        "context": {
            "suite_id": ctx.suite_id,
            "case_id": ctx.case_id,
            "repo_name": ctx.repo_name,
            "tools": list(ctx.tools),
            "mode": ctx.mode,
            "tolerance": ctx.tolerance,
        },
        "summary": {
            "tool_count": len(ctx.tools),
            "triage_items": len(triage),
            "top_agreement": int(triage[0]["tool_count"]) if triage else 0,
        },
        "artifacts": store.artifact_paths_rel(ctx.out_dir),
        "overview": overview,
        "tool_profile": tool_profile,
        "pairwise_agreement": pairwise,
        "taxonomy": taxonomy,
        "triage_queue_top": triage_top,
    }
    return pack


@register_stage(
    "benchmark_pack",
    kind="reporting",
    description="Write a single benchmark_pack.json for ingestion/reporting.",
)
def stage_benchmark_pack(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    pack = build_benchmark_pack(ctx, store)
    out_path = Path(ctx.out_dir) / "benchmark_pack.json"
    write_json(out_path, pack)
    store.add_artifact("benchmark_pack", out_path)
    store.put("benchmark_pack", pack)
    return {"bytes": out_path.stat().st_size if out_path.exists() else 0}


def main(argv: List[str] | None = None) -> None:  # pragma: no cover
    ap = argparse.ArgumentParser(description="Build benchmark_pack.json from an analysis directory.")
    ap.add_argument("--analysis-dir", required=True, help="Path to a case analysis dir (contains outputs)")
    args = ap.parse_args(argv)

    # Minimal: rehydrate from files when possible.
    analysis_dir = Path(args.analysis_dir)
    out_path = analysis_dir / "benchmark_pack.json"
    if out_path.exists():
        print(out_path.read_text(encoding="utf-8"))
        return
    raise SystemExit(f"benchmark_pack.json not found in: {analysis_dir}")
