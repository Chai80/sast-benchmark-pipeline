from __future__ import annotations

"""pipeline.analysis.stages.gt.io

Persistence helpers for the GT scoring stage.
"""

from pathlib import Path
from typing import Any, Mapping, Sequence

from pipeline.analysis.framework import AnalysisContext, ArtifactStore
from pipeline.analysis.io.write_artifacts import write_csv, write_json

from ..common.store_keys import StoreKeys


def write_gt_score_artifacts(
    ctx: AnalysisContext,
    store: ArtifactStore,
    *,
    gt_dir: Path,
    summary: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    gap_summary: Mapping[str, Any],
    gap_rows: Sequence[Mapping[str, Any]],
) -> None:
    """Write GT artifacts under <case_dir>/gt.

    This function does not change any scoring behavior; it only centralizes the
    JSON/CSV writing and ArtifactStore registrations.
    """

    gt_dir.mkdir(parents=True, exist_ok=True)

    out_json = gt_dir / "gt_score.json"
    out_csv = gt_dir / "gt_score.csv"
    out_gap_json = gt_dir / "gt_gap_queue.json"
    out_gap_csv = gt_dir / "gt_gap_queue.csv"

    formats = ctx.formats or ("json",)

    if "json" in formats:
        write_json(out_json, {"summary": dict(summary), "rows": list(rows)})
        store.add_artifact("gt_score_json", out_json)

        write_json(
            out_gap_json,
            {
                "schema_version": "gt_gap_queue_v1",
                "summary": dict(gap_summary),
                "rows": list(gap_rows),
            },
        )
        store.add_artifact("gt_gap_queue_json", out_gap_json)

    if "csv" in formats:
        write_csv(
            out_csv,
            list(rows),
            fieldnames=[
                "gt_id",
                "track",
                "set",
                "file",
                "start_line",
                "end_line",
                "matched",
                "matched_tool_count",
                "matched_tools",
            ],
        )
        store.add_artifact("gt_score_csv", out_csv)

        write_csv(
            out_gap_csv,
            list(gap_rows),
            fieldnames=[
                "gt_id",
                "track",
                "set",
                "file",
                "start_line",
                "end_line",
                "matched",
                "matched_tool_count",
                "matched_tools",
                "reason",
                "filtered_by",
            ],
        )
        store.add_artifact("gt_gap_queue_csv", out_gap_csv)


def cache_gt_score_results(
    store: ArtifactStore,
    *,
    summary: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    gap_rows: Sequence[Mapping[str, Any]],
) -> None:
    """Cache stage outputs in the store for exporters (no disk reads)."""

    store.put(StoreKeys.GT_SCORE_SUMMARY, dict(summary))
    store.put(StoreKeys.GT_SCORE_ROWS, [dict(r) for r in rows])
    store.put(StoreKeys.GT_GAP_ROWS, [dict(r) for r in gap_rows])
