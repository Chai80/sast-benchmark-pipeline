from __future__ import annotations

"""pipeline.analysis.exports.benchmark_pack

A compact, stable JSON pack intended for downstream dashboards/UX.

This export intentionally mirrors "what you usually want" for a case:
- overview hotspots
- high-level tool profile stats
- pairwise agreement summary
- taxonomy distribution
- triage top-N
- optional GT scoring summary (if gt_score stage ran)

Adding new keys is preferred over changing existing ones.
"""

from typing import Any, Dict

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_export


def _pick(d: Dict[str, Any], *keys: str) -> Dict[str, Any]:
    return {k: d.get(k) for k in keys if k in d}


@register_export("benchmark_pack")
def build_benchmark_pack(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    overview = store.get("overview_report") or {}
    tool_profile = store.get("tool_profile") or {}
    pairwise = store.get("pairwise_agreement") or {}
    taxonomy = store.get("taxonomy") or {}
    triage_rows = store.get("triage_rows") or []

    tool_profile_summary = {
        "tool_count": tool_profile.get("tool_count"),
        "tools": tool_profile.get("tools"),
        "by_tool": tool_profile.get("by_tool"),
    }

    pairwise_summary = {
        "pairwise": pairwise.get("pairwise"),
        "average_overlap": pairwise.get("average_overlap"),
    }

    taxonomy_summary = {
        "top_categories": taxonomy.get("top_categories"),
        "top_cwes": taxonomy.get("top_cwes"),
    }

    triage_queue_top = triage_rows[:25]

    gt_score_summary = store.get("gt_score_summary")

    return {
        "schema_version": "benchmark_pack_v1",
        "context": {
            "suite_id": ctx.suite_id,
            "case_id": ctx.case_id,
            "repo_name": ctx.repo_name,
            "tools": list(ctx.tools),
            "mode": ctx.mode,
            # clustering tolerance
            "tolerance": int(ctx.tolerance),
            # GT scoring tolerance (used only by gt_score stage)
            "gt_tolerance": int(getattr(ctx, "gt_tolerance", 0)),
            # scope filtering
            "exclude_prefixes": list(getattr(ctx, "exclude_prefixes", ()) or ()),
            "include_harness": bool(getattr(ctx, "include_harness", False)),
        },
        "overview": overview,
        "tool_profile": tool_profile_summary,
        "pairwise": pairwise_summary,
        "taxonomy": taxonomy_summary,
        "triage_queue_top": triage_queue_top,
        # Optional
        "gt_score": gt_score_summary,
        "artifacts": store.artifact_paths_rel(ctx.out_dir),
        "warnings": list(store.warnings),
    }
