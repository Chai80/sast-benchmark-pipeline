from __future__ import annotations

"""pipeline.analysis.stages.consensus

Consensus (multi-tool agreement) scoring.

This stage is intentionally **GT-free**.

It answers a different question than GT scoring:

  - GT scoring: "Did a tool find the vulnerabilities we *know* exist?"
  - Consensus:  "Which hotspots do multiple tools agree on?"

Because it operates purely on clustered finding locations, it remains
scanner-agnostic and automatically extends to new scanners (e.g., Aikido)
as long as they emit normalized findings.

Outputs
-------
Writes:
  - <analysis_dir>/consensus_queue.json
  - <analysis_dir>/consensus_queue.csv

Both are later reorganized by :func:`pipeline.analysis.io.organize_outputs`
so the CSV ends up under ``analysis/_tables/``.
"""

import argparse
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json
from pipeline.scanners import DEFAULT_SCANNERS_CSV

from .common.locations import ensure_location_clusters
from .common.severity import max_severity
from .common.store_keys import StoreKeys


def _sample_field(items: List[Dict[str, Any]], field: str) -> str:
    for it in items or []:
        v = it.get(field)
        if v:
            return str(v)
    return ""


def _consensus_level(tool_count: int, total_tools: int) -> str:
    """Bucket tool agreement into a small set of labels.

    These buckets are intentionally simple so consumers can use them directly
    in dashboards/triage without remembering numeric thresholds.
    """
    if tool_count <= 0:
        return "none"
    if tool_count == 1:
        return "single"
    if total_tools > 0 and tool_count >= total_tools:
        return "unanimous"
    return "multi"


@register_stage(
    "consensus_queue",
    kind="analysis",
    description="Compute multi-tool agreement (consensus) per clustered location.",
)
def stage_consensus(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    clusters = ensure_location_clusters(ctx, store)

    total_tools = len(ctx.tools)

    rows: List[Dict[str, Any]] = []
    by_tool_count: Counter[int] = Counter()

    for c in clusters:
        items = list(c.get("items") or [])
        tool_count = int(c.get("tool_count") or 0)
        by_tool_count[tool_count] += 1

        # Optional UI fields (helpful for human triage).
        sev, _rank = max_severity(items)
        rows.append(
            {
                "file_path": c.get("file_path"),
                "start_line": c.get("start_line"),
                "end_line": c.get("end_line"),
                "cluster_id": c.get("cluster_id"),
                "tools": ",".join(c.get("tools") or []),
                "tool_count": tool_count,
                "agreement_fraction": (tool_count / total_tools) if total_tools else 0.0,
                "consensus_level": _consensus_level(tool_count, total_tools),
                "total_findings": len(items),
                "max_severity": sev,
                "sample_rule_id": _sample_field(items, "rule_id"),
                "sample_title": _sample_field(items, "title"),
            }
        )

    # Rank by agreement first, then severity, then total findings.
    def _sev_rank(row: Dict[str, Any]) -> int:
        s = str(row.get("max_severity") or "").upper().strip()
        if s == "HIGH":
            return 3
        if s == "MEDIUM":
            return 2
        if s == "LOW":
            return 1
        return 0

    rows.sort(
        key=lambda r: (
            -int(r.get("tool_count") or 0),
            -_sev_rank(r),
            -int(r.get("total_findings") or 0),
            str(r.get("file_path") or ""),
            int(r.get("start_line") or 0),
        )
    )
    for i, r in enumerate(rows, start=1):
        r["rank"] = i

    store.put(StoreKeys.CONSENSUS_ROWS, rows)
    summary = {
        "clusters": len(rows),
        "tools": total_tools,
        "top_tool_count": int(rows[0]["tool_count"]) if rows else 0,
        "by_tool_count": {str(k): int(v) for k, v in sorted(by_tool_count.items(), key=lambda kv: kv[0])},
    }
    store.put(StoreKeys.CONSENSUS_SUMMARY, summary)

    out_json = Path(ctx.out_dir) / "consensus_queue.json"
    out_csv = Path(ctx.out_dir) / "consensus_queue.csv"

    if "json" in ctx.formats:
        write_json(out_json, {"summary": summary, "rows": rows})
        store.add_artifact("consensus_queue_json", out_json)
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
                "agreement_fraction",
                "consensus_level",
                "tools",
                "total_findings",
                "max_severity",
                "sample_rule_id",
                "sample_title",
                "cluster_id",
            ],
        )
        store.add_artifact("consensus_queue_csv", out_csv)

    return summary


def main(argv: List[str] | None = None) -> None:  # pragma: no cover
    ap = argparse.ArgumentParser(description="Generate consensus queue (wrapper around analysis suite).")
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


if __name__ == "__main__":  # pragma: no cover
    main()
