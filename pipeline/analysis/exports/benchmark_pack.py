from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_json
from pipeline.analysis.utils.owasp import infer_owasp


def _load_gt_score_summary(ctx: AnalysisContext) -> Optional[Dict[str, Any]]:
    """
    Optional helper: if gt_score ran, it writes <case_dir>/gt/gt_score.json.
    We read it here so benchmark_pack can surface gt_score.summary without
    requiring store-coupling.
    """
    out_dir = Path(ctx.out_dir)
    if out_dir.name != "analysis":
        return None
    case_dir = out_dir.parent
    p = case_dir / "gt" / "gt_score.json"
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("summary"), dict):
            return data["summary"]
        if isinstance(data, dict):
            return data
    except Exception:
        return None
    return None


def build_benchmark_pack(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    """Build a single JSON object suitable for DB ingestion / UX."""
    owasp_id, owasp_title = infer_owasp(ctx.case_id, out_dir=Path(ctx.out_dir))

    overview = store.get("overview_report") or {}
    tool_profile = store.get("tool_profile_rows") or []
    pairwise = store.get("pairwise_rows") or []
    taxonomy = store.get("taxonomy_rows") or []
    triage = store.get("triage_rows") or []
    consensus = store.get("consensus_rows") or []
    consensus_summary = store.get("consensus_summary") or {}
    gt_summary = store.get("gt_score_summary") or {}

    # Keep pack relatively small: include top-N triage rows.
    triage_top = list(triage)[:200]
    consensus_top = list(consensus)[:200]

    # Optional GT summary if present
    gt_score_summary = store.get("gt_score_summary")
    if not isinstance(gt_score_summary, dict):
        gt_score_summary = _load_gt_score_summary(ctx)

    pack: Dict[str, Any] = {
        "schema_version": "benchmark_pack_v1",
        "context": {
            "suite_id": ctx.suite_id,
            "case_id": ctx.case_id,
            "repo_name": ctx.repo_name,
            "tools": list(ctx.tools),
            "mode": ctx.mode,
<<<<<<< ours
            # clustering tolerance
            "tolerance": int(ctx.tolerance),

            # Optional (new, backwards-compatible additions)
            "gt_tolerance": int(getattr(ctx, "gt_tolerance", 0) or 0),
            "exclude_prefixes": list(getattr(ctx, "exclude_prefixes", ()) or ()),
            "include_harness": bool(getattr(ctx, "include_harness", False)),

            # Optional (new): OWASP Top 10 context for OWASP micro-suite cases
            "owasp_id": owasp_id,
            "owasp_title": owasp_title,
=======
            "tolerance": ctx.tolerance,
            "gt_tolerance": int((ctx.config or {}).get("gt_tolerance") or 0),
            "gt_source": str((ctx.config or {}).get("gt_source") or "auto"),
>>>>>>> theirs
        },
        "summary": {
            "tool_count": len(ctx.tools),
            "triage_items": len(triage),
            "top_agreement": int(triage[0]["tool_count"]) if triage else 0,
            "consensus_items": len(consensus),
            "top_consensus": int(consensus[0]["tool_count"]) if consensus else 0,
            "gt": gt_summary or None,
        },
        "artifacts": store.artifact_paths_rel(ctx.out_dir),
        "overview": overview,
        "tool_profile": tool_profile,
        "pairwise_agreement": pairwise,
        "taxonomy": taxonomy,
        "triage_queue_top": triage_top,
<<<<<<< ours

        # Optional (new): GT scoring summary (includes per_tool_recall if present)
        "gt_score": gt_score_summary,
=======
        "consensus": {
            "summary": consensus_summary,
            "queue_top": consensus_top,
        },
>>>>>>> theirs
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

    analysis_dir = Path(args.analysis_dir)
    out_path = analysis_dir / "benchmark_pack.json"
    if out_path.exists():
        print(out_path.read_text(encoding="utf-8"))
        return
    raise SystemExit(f"benchmark_pack.json not found in: {analysis_dir}")
