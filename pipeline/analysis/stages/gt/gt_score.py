from __future__ import annotations

"""pipeline.analysis.stages.gt_score

Ground-truth (GT) scoring stage.

Desired behavior (GT optional)
------------------------------
GT scoring is optional and controlled by the presence of a GT catalog for a case.

- --gt-source yaml:
  Run only if a GT catalog exists at <case_dir>/gt/gt_catalog.yaml or .yml.
  If missing, skip with reason: no_gt_catalog_yaml.

- --gt-source auto:
  Try markers first (in-repo DURINN_GT markers or captured gt_markers.json),
  then YAML if present, otherwise skip with reason: no_gt.

- --gt-source markers:
  Require markers; if none, skip with reason: no_gt_markers.

Suite authoring notes (YAML vs markers)
--------------------------------------
There are two supported ways to define ground-truth for a case/suite:

1) Marker-based GT (recommended for branch-per-case suites)

   Add inline markers in the case repo's source files, for example::

       # DURINN_GT id=a07_01 track=sast set=core owasp=A07

   This works well when each case is a git branch, because GT travels with the
   code. Marker suites will NOT score if you force ``--gt-source=yaml``.

2) YAML catalog GT (recommended for catalog-driven benchmarks)

   Provide a catalog file in the repo (typically ``benchmark/gt_catalog.yaml``
   or ``benchmark/gt_catalog.yml``). When a case is materialized, the catalog is
   copied into ``<case_dir>/gt/gt_catalog.yaml`` and used by the scorer.

In short: marker suites are easiest for branch-per-case designs; YAML catalogs
are easiest when you want GT maintained in one place outside the code.

Outputs (when scoring runs)
---------------------------
Writes under <case_dir>/gt/:
- gt_score.json + gt_score.csv
- gt_gap_queue.json + gt_gap_queue.csv

Gap queue reasons (per GT item that is NOT matched):
- no_findings
- filtered_out
- found_but_not_matched

Tolerance
---------
- ctx.gt_tolerance (or --gt-tolerance) affects ONLY GT matching.
- ctx.tolerance (or --tolerance) is used for clustering/triage elsewhere.
"""

from typing import Any, Dict

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage

from ..common.locations import build_location_items
from ..common.store_keys import StoreKeys

from .gap_queue import build_gap_queue
from .io import cache_gt_score_results, write_gt_score_artifacts
from .matching import score_gt_items, tool_locations
from .normalize import filter_gt_items_by_track, normalize_gt_items
from .sources import case_scoring_track, choose_gt_source, find_case_dir, load_case_json


@register_stage(
    "gt_score",
    kind="analysis",
    description="Optional GT scoring (markers/YAML) for a suite case.",
    requires=(StoreKeys.LOCATION_ITEMS,),
    produces=(
        StoreKeys.GT_SCORE_ROWS,
        StoreKeys.GT_SCORE_SUMMARY,
        StoreKeys.GT_GAP_ROWS,
    ),
)
def stage_gt_score(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    cfg = dict(ctx.config or {})
    gt_source_mode = str(cfg.get("gt_source") or "auto").strip().lower()

    # Normalize synonyms
    if gt_source_mode in ("off", "none", "disable", "disabled"):
        gt_source_mode = "none"

    if gt_source_mode not in ("auto", "markers", "yaml", "none"):
        store.add_warning(
            f"gt_score: unknown gt_source={gt_source_mode!r}; using 'auto'"
        )
        gt_source_mode = "auto"

    if gt_source_mode == "none":
        return {
            "status": "skipped",
            "reason": "gt_disabled",
            "gt_source_mode": gt_source_mode,
        }

    case_dir = find_case_dir(ctx)
    if not case_dir:
        return {
            "status": "skipped",
            "reason": "not_suite_layout",
            "gt_source_mode": gt_source_mode,
        }

    gt_dir = case_dir / "gt"
    case_json = load_case_json(case_dir)
    scoring_track = case_scoring_track(case_json)
    scoring_track_n = scoring_track.strip().lower() if scoring_track else None

    # --- Choose GT source -------------------------------------------------
    gt_source_used, raw_items, gt_catalog_path, skip = choose_gt_source(
        gt_source_mode,
        gt_dir=gt_dir,
        case_json=case_json,
    )
    if skip:
        return skip

    # --- Normalize + filter GT items -------------------------------------
    gt_items = normalize_gt_items(raw_items, repo_name=ctx.repo_name)
    if not gt_items:
        # Should not happen often, but keep behavior explicit.
        if gt_source_mode == "yaml":
            return {
                "status": "skipped",
                "reason": "empty_gt_catalog_yaml",
                "gt_source_mode": "yaml",
                "gt_catalog_path": str(gt_catalog_path) if gt_catalog_path else None,
            }
        if gt_source_mode == "markers":
            return {
                "status": "skipped",
                "reason": "no_gt_markers",
                "gt_source_mode": "markers",
            }
        return {
            "status": "skipped",
            "reason": "no_gt",
            "gt_source_mode": gt_source_mode,
        }

    filtered_out_by_track = 0
    if scoring_track_n:
        gt_items, filtered_out_by_track = filter_gt_items_by_track(
            gt_items, scoring_track_n
        )
        if not gt_items:
            return {
                "status": "skipped",
                "reason": "no_gt_for_track",
                "track": scoring_track,
                "filtered_out_by_track": int(filtered_out_by_track),
                "gt_source_mode": gt_source_mode,
                "gt_source": gt_source_used or "unknown",
                "gt_catalog_path": str(gt_catalog_path) if gt_catalog_path else None,
            }

    # --- Build prediction locations (filtered) ---------------------------
    # Uses ctx.mode and ctx.exclude_prefixes.
    location_items = build_location_items(ctx, store)
    tool_locs = tool_locations(location_items)

    # --- Score ------------------------------------------------------------
    gt_tol = int(getattr(ctx, "gt_tolerance", 0) or 0)
    if gt_tol < 0:
        gt_tol = 0

    (
        rows,
        matched_gt_items,
        per_tool_matched,
        by_set_total,
        by_set_matched,
        by_track_total,
        by_track_matched,
    ) = score_gt_items(
        gt_items=gt_items,
        tool_locs=tool_locs,
        gt_tolerance=gt_tol,
    )

    total_gt_items = len(rows)
    tools = list(ctx.tools or ())
    per_tool_recall = {
        str(t): (float(per_tool_matched.get(str(t), 0)) / float(total_gt_items))
        if total_gt_items
        else 0.0
        for t in tools
    }

    summary: Dict[str, Any] = {
        "status": "ok",
        "gt_source_mode": gt_source_mode,
        "gt_source": gt_source_used or "unknown",
        "gt_catalog_path": str(gt_catalog_path) if gt_catalog_path else None,
        "gt_tolerance": int(gt_tol),
        "scoring_track": scoring_track_n,
        "filtered_out_by_track": int(filtered_out_by_track),
        "total_gt_items": int(total_gt_items),
        "matched_gt_items": int(matched_gt_items),
        "match_rate": (float(matched_gt_items) / float(total_gt_items))
        if total_gt_items
        else 0.0,
        "per_tool_matched": {
            str(t): int(per_tool_matched.get(str(t), 0)) for t in tools
        },
        "per_tool_recall": {k: round(float(v), 6) for k, v in per_tool_recall.items()},
        "by_set": {
            s: {"total": int(by_set_total[s]), "matched": int(by_set_matched[s])}
            for s in sorted(by_set_total.keys())
        },
        "by_track": {
            tr: {"total": int(by_track_total[tr]), "matched": int(by_track_matched[tr])}
            for tr in sorted(by_track_total.keys())
        },
    }

    # --- Gap queue --------------------------------------------------------
    gap_rows, gap_summary = build_gap_queue(
        ctx, rows=rows, location_items=location_items
    )
    summary["gap_summary"] = gap_summary

    # --- Write outputs ----------------------------------------------------
    write_gt_score_artifacts(
        ctx,
        store,
        gt_dir=gt_dir,
        summary=summary,
        rows=rows,
        gap_summary=gap_summary,
        gap_rows=gap_rows,
    )

    # Cache for exporters
    cache_gt_score_results(store, summary=summary, rows=rows, gap_rows=gap_rows)

    return summary
