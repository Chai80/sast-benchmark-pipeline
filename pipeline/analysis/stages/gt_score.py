from __future__ import annotations

"""pipeline.analysis.stages.gt_score

Ground-truth scoring stage (v1).

This stage is suite-layout aware. It expects the v2 case layout where the
analysis output directory is:
  runs/suites/<suite_id>/cases/<case_id>/analysis

GT inputs are expected under:
  <case_dir>/gt/

Inputs (preferred order)
------------------------
- gt_markers.json (captured from benchmark/gt_markers.json during case run)
- gt_catalog.yaml (optional, legacy)
- suite_sets.yaml (optional): annotates GT items with {set,track}

Outputs
-------
- <case_dir>/gt/gt_score.json
- <case_dir>/gt/gt_score.csv
- <case_dir>/gt/gt_gap_queue.json
- <case_dir>/gt/gt_gap_queue.csv

Tolerance
---------
- ctx.gt_tolerance is used ONLY for GT matching.
- ctx.tolerance is used for clustering/triage UX and does not affect GT scoring.
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json
from pipeline.analysis.utils.filters import filter_findings
from pipeline.analysis.utils.path_norm import normalize_file_path

from pipeline.analysis.stages._shared import build_location_items, load_normalized_json


def _find_case_dir(ctx: AnalysisContext) -> Optional[Path]:
    # v2 layout: analysis output lives under <case_dir>/analysis
    if ctx.out_dir.name == "analysis" and ctx.out_dir.parent:
        return ctx.out_dir.parent
    return None


def _load_case_json(case_dir: Path) -> Dict[str, Any]:
    p = case_dir / "case.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_yaml(path: Path) -> Optional[Any]:
    try:
        import yaml  # type: ignore

        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _coerce_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _load_gt_items(case_dir: Path) -> List[Dict[str, Any]]:
    """Load GT items from the case's captured GT directory."""
    gt_dir = case_dir / "gt"
    gt_markers = gt_dir / "gt_markers.json"
    gt_catalog = gt_dir / "gt_catalog.yaml"

    items: List[Dict[str, Any]] = []

    if gt_markers.exists():
        try:
            data = json.loads(gt_markers.read_text(encoding="utf-8"))
        except Exception:
            data = None
        if isinstance(data, list):
            for row in data:
                if not isinstance(row, dict):
                    continue
                item = dict(row)

                # Normalize file field names
                if "file" not in item and "file_path" in item:
                    item["file"] = item.get("file_path")

                # Normalize line field names into start/end line
                line = item.get("line")
                if line is None:
                    line = item.get("line_number")
                if line is not None:
                    ln = _coerce_int(line, default=0)
                    item["start_line"] = ln
                    item["end_line"] = ln
                elif "start_line" in item:
                    item["start_line"] = _coerce_int(item.get("start_line"), default=0)
                    item["end_line"] = _coerce_int(item.get("end_line") or item.get("start_line"), default=0)

                items.append(item)

    elif gt_catalog.exists():
        data = _load_yaml(gt_catalog)
        if isinstance(data, list):
            for row in data:
                if not isinstance(row, dict):
                    continue
                item = dict(row)
                if "file" not in item and "file_path" in item:
                    item["file"] = item.get("file_path")

                # Catalog format might provide line_number; normalize like markers.
                line = item.get("line")
                if line is None:
                    line = item.get("line_number")
                if line is not None:
                    ln = _coerce_int(line, default=0)
                    item["start_line"] = ln
                    item["end_line"] = ln
                elif "start_line" in item:
                    item["start_line"] = _coerce_int(item.get("start_line"), default=0)
                    item["end_line"] = _coerce_int(item.get("end_line") or item.get("start_line"), default=0)

                items.append(item)

    return items


def _normalize_suite_sets_id(v: Any) -> str:
    return str(v or "").strip()


def _load_suite_sets_meta(case_dir: Path) -> Dict[str, Dict[str, str]]:
    """Load optional suite_sets.yaml captured for this case.

    Returns mapping: gt_id -> {"set": <set>, "track": <track>}.

    The YAML format may evolve; this parser is intentionally permissive.
    """
    gt_dir = case_dir / "gt"
    p = gt_dir / "suite_sets.yaml"
    if not p.exists():
        p = gt_dir / "suite_sets.yml"
    if not p.exists():
        return {}

    data = _load_yaml(p)
    if data is None:
        return {}

    mapping: Dict[str, Dict[str, str]] = {}

    def add_ids(ids: Any, *, set_name: Optional[str] = None, track_name: Optional[str] = None) -> None:
        if ids is None:
            return
        if isinstance(ids, dict):
            # Either {id: {...}} or a single item {id:..., set:..., track:...}
            if "id" in ids:
                gid = _normalize_suite_sets_id(ids.get("id"))
                if not gid:
                    return
                meta = mapping.setdefault(gid, {})
                s = ids.get("set") or set_name
                t = ids.get("track") or track_name
                if s:
                    meta["set"] = str(s).strip()
                if t:
                    meta["track"] = str(t).strip()
                return

            for k, v in ids.items():
                gid = _normalize_suite_sets_id(k)
                if not gid:
                    continue
                meta = mapping.setdefault(gid, {})
                if isinstance(v, dict):
                    s = v.get("set") or set_name
                    t = v.get("track") or track_name
                    if s:
                        meta["set"] = str(s).strip()
                    if t:
                        meta["track"] = str(t).strip()
                else:
                    # v is likely truthy/falsey or a label; treat key membership.
                    if set_name:
                        meta["set"] = str(set_name).strip()
                    if track_name:
                        meta["track"] = str(track_name).strip()
            return

        if isinstance(ids, (list, tuple)):
            for row in ids:
                add_ids(row, set_name=set_name, track_name=track_name)
            return

        # Scalar id string
        gid = _normalize_suite_sets_id(ids)
        if not gid:
            return
        meta = mapping.setdefault(gid, {})
        if set_name:
            meta["set"] = str(set_name).strip()
        if track_name:
            meta["track"] = str(track_name).strip()

    if isinstance(data, dict):
        # Common shapes:
        # - {items: {GT001: {set: core, track: sast}}}
        # - {items: [{id: GT001, set: core, track: sast}]}
        # - {tracks: {sast: {core: [GT001], extended: [...]}}}
        # - {sets: {core: [...], extended: [...]}}
        items = data.get("items")
        if items is not None:
            add_ids(items)
            return mapping

        tracks = data.get("tracks")
        if isinstance(tracks, dict):
            for track_name, tv in tracks.items():
                if isinstance(tv, dict):
                    # track -> sets mapping
                    if "sets" in tv and isinstance(tv["sets"], dict):
                        for set_name, ids in tv["sets"].items():
                            add_ids(ids, set_name=str(set_name), track_name=str(track_name))
                    else:
                        for set_name, ids in tv.items():
                            add_ids(ids, set_name=str(set_name), track_name=str(track_name))
                else:
                    add_ids(tv, track_name=str(track_name))
            return mapping

        sets = data.get("sets")
        if isinstance(sets, dict):
            for set_name, ids in sets.items():
                add_ids(ids, set_name=str(set_name), track_name=str(data.get("track") or "") or None)
            return mapping

        # Fallback: treat top-level keys as set names
        for k, v in data.items():
            if k in {"track", "default_track"}:
                continue
            add_ids(v, set_name=str(k), track_name=str(data.get("track") or "") or None)

    return mapping


def _annotate_gt_items(
    gt_items: List[Dict[str, Any]],
    *,
    repo_name: str,
    scoring_track: Optional[str],
    suite_sets_meta: Mapping[str, Mapping[str, str]],
) -> List[Dict[str, Any]]:
    """Annotate GT items with normalized file paths and set/track metadata."""
    out: List[Dict[str, Any]] = []
    scoring_track_n = (str(scoring_track or "").strip().lower() or None)

    for it in gt_items:
        gid = str(it.get("id") or it.get("gt_id") or "").strip()
        if not gid:
            continue

        file_raw = str(it.get("file") or it.get("file_path") or "").strip()
        fp = normalize_file_path(file_raw, repo_name=repo_name)
        if not fp:
            continue

        start_line = _coerce_int(it.get("start_line") or it.get("line") or it.get("line_number"), default=0)
        end_line = _coerce_int(it.get("end_line") or start_line, default=start_line)
        if end_line < start_line:
            start_line, end_line = end_line, start_line

        meta = suite_sets_meta.get(gid, {}) or {}

        # Track: prefer explicit item field, then suite_sets, then scoring_track.
        track = str(it.get("track") or meta.get("track") or (scoring_track_n or "unknown")).strip()
        track_n = track.lower() if track else "unknown"

        # Set: prefer explicit item field, then suite_sets.
        set_name = str(it.get("set") or meta.get("set") or "unknown").strip() or "unknown"

        out.append(
            {
                **it,
                "id": gid,
                "file": fp,
                "start_line": int(start_line),
                "end_line": int(end_line),
                "track": track_n,
                "set": set_name,
            }
        )

    # Track filter (if case declares a scoring track)
    if scoring_track_n:
        out = [it for it in out if str(it.get("track") or "unknown").strip().lower() == scoring_track_n]

    return out


def _tool_locations(items: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    by_tool: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for it in items:
        tool = str(it.get("tool") or "")
        if not tool:
            continue
        fp = str(it.get("file_path") or "")
        ln = _coerce_int(it.get("line_number"), default=0)
        by_tool[tool].append({"file": fp, "line": ln})
    return by_tool


def _match_tools_for_gt(
    *,
    gt_file: str,
    gt_start: int,
    gt_end: int,
    tool_locs: Mapping[str, Sequence[Mapping[str, Any]]],
    tol: int,
) -> List[str]:
    matched: List[str] = []
    for tool, locs in tool_locs.items():
        for loc in locs:
            fp = str(loc.get("file") or "")
            ln = _coerce_int(loc.get("line"), default=0)
            if fp != gt_file:
                continue
            if ln >= (gt_start - tol) and ln <= (gt_end + tol):
                matched.append(tool)
                break
    return sorted(set(matched))


def _summarize_by_field(rows: Sequence[Mapping[str, Any]], field: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        key = str(r.get(field) or "unknown")
        bucket = out.setdefault(key, {"total": 0, "matched": 0})
        bucket["total"] += 1
        if bool(r.get("matched")):
            bucket["matched"] += 1

    # add rate
    for k, v in out.items():
        total = int(v.get("total") or 0)
        matched = int(v.get("matched") or 0)
        v["match_rate"] = round(matched / total, 6) if total else 0.0
        out[k] = v
    return out


def _build_location_items_without_scope(
    *,
    ctx: AnalysisContext,
    apply_mode_filter: bool,
) -> List[Dict[str, Any]]:
    """Load normalized findings and build location items.

    This helper intentionally bypasses ctx.exclude_prefixes so we can detect
    whether a GT miss is due to filtering (mode or scope).
    """
    items: List[Dict[str, Any]] = []

    for tool, p in ctx.normalized_paths.items():
        data = load_normalized_json(p)
        findings = data.get("findings") or []
        if not isinstance(findings, list):
            continue

        if apply_mode_filter:
            findings = filter_findings(tool, findings, mode=ctx.mode)

        for f in findings:
            if not isinstance(f, dict):
                continue
            fp = normalize_file_path(str(f.get("file_path") or ""), repo_name=ctx.repo_name)
            items.append(
                {
                    "tool": tool,
                    "file_path": fp,
                    "line_number": f.get("line_number"),
                }
            )

    return items


@register_stage("gt_score", kind="analysis")
def stage_gt_score(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    case_dir = _find_case_dir(ctx)
    if not case_dir:
        store.add_warning("gt_score: skipped (not suite layout)")
        return {"skipped": True, "reason": "not_suite_layout"}

    case_json = _load_case_json(case_dir)

    scoring_track = None
    if isinstance(case_json, dict):
        scoring_track = case_json.get("track") or (case_json.get("tags") or {}).get("track")

    raw_gt_items = _load_gt_items(case_dir)
    if not raw_gt_items:
        store.add_warning("gt_score: no GT items found")
        return {"skipped": True, "reason": "no_gt"}

    suite_sets_meta = _load_suite_sets_meta(case_dir)
    gt_items = _annotate_gt_items(
        raw_gt_items,
        repo_name=ctx.repo_name,
        scoring_track=scoring_track,
        suite_sets_meta=suite_sets_meta,
    )

    if scoring_track and not gt_items:
        store.add_warning(f"gt_score: no GT items for track '{scoring_track}'")
        return {"skipped": True, "reason": "no_gt_for_track"}

    # Build location items (FULL filters: mode + scope)
    location_items = build_location_items(ctx, store)
    tool_locs = _tool_locations(location_items)

    tol = int(getattr(ctx, "gt_tolerance", 0) or 0)

    rows: List[Dict[str, Any]] = []
    for gt in gt_items:
        gt_file = str(gt.get("file") or "")
        gt_start = _coerce_int(gt.get("start_line"), default=0)
        gt_end = _coerce_int(gt.get("end_line"), default=gt_start)

        matched_tools = _match_tools_for_gt(
            gt_file=gt_file,
            gt_start=gt_start,
            gt_end=gt_end,
            tool_locs=tool_locs,
            tol=tol,
        )

        rows.append(
            {
                "gt_id": str(gt.get("id") or ""),
                "set": str(gt.get("set") or "unknown"),
                "track": str(gt.get("track") or "unknown"),
                "file": gt_file,
                "start_line": gt_start,
                "end_line": gt_end,
                "matched": bool(matched_tools),
                "matched_tool_count": len(matched_tools),
                "matched_tools": ",".join(matched_tools),
            }
        )

    total = len(rows)
    matched_count = sum(1 for r in rows if r.get("matched"))
    match_rate = round(matched_count / total, 6) if total else 0.0

    by_set = _summarize_by_field(rows, "set")
    by_track = _summarize_by_field(rows, "track")

    # Per-tool recall (tool-level contribution to GT match)
    per_tool: Dict[str, Dict[str, Any]] = {}
    for tool in ctx.tools:
        m = 0
        for r in rows:
            tools_s = str(r.get("matched_tools") or "")
            tools = [t for t in tools_s.split(",") if t]
            if tool in tools:
                m += 1
        per_tool[tool] = {
            "matched": int(m),
            "total": int(total),
            "recall": round(m / total, 6) if total else 0.0,
        }

    # GT gap queue (unmatched items)
    # Detect whether gaps are due to filtering by comparing against raw/mode-only items.
    raw_items = _build_location_items_without_scope(ctx=ctx, apply_mode_filter=False)
    mode_items = _build_location_items_without_scope(ctx=ctx, apply_mode_filter=True)

    raw_locs = _tool_locations(raw_items)
    mode_locs = _tool_locations(mode_items)

    gap_rows: List[Dict[str, Any]] = []
    for r in rows:
        if r.get("matched"):
            continue
        gt_file = str(r.get("file") or "")
        gt_start = _coerce_int(r.get("start_line"), default=0)
        gt_end = _coerce_int(r.get("end_line"), default=gt_start)

        raw_tools = _match_tools_for_gt(
            gt_file=gt_file,
            gt_start=gt_start,
            gt_end=gt_end,
            tool_locs=raw_locs,
            tol=tol,
        )
        mode_tools = _match_tools_for_gt(
            gt_file=gt_file,
            gt_start=gt_start,
            gt_end=gt_end,
            tool_locs=mode_locs,
            tol=tol,
        )

        reason = "no_findings"
        filtered_out_by: Optional[str] = None
        if raw_tools:
            reason = "filtered_out"
            filtered_out_by = "mode" if not mode_tools else "scope"

        gap_rows.append(
            {
                "gt_id": str(r.get("gt_id") or ""),
                "set": str(r.get("set") or "unknown"),
                "track": str(r.get("track") or "unknown"),
                "file": gt_file,
                "start_line": gt_start,
                "end_line": gt_end,
                "reason": reason,
                "filtered_out_by": filtered_out_by or "",
                "raw_matched_tools": ",".join(raw_tools),
                "mode_matched_tools": ",".join(mode_tools),
            }
        )

    gap_total = len(gap_rows)
    gap_filtered_out = sum(1 for g in gap_rows if g.get("reason") == "filtered_out")

    summary: Dict[str, Any] = {
        "schema_version": "gt_score_v1",
        "gt_total": int(total),
        "matched": int(matched_count),
        "match_rate": float(match_rate),
        "gt_tolerance": int(tol),
        "scoring_track": str(scoring_track or ""),
        "by_set": by_set,
        "by_track": by_track,
        "per_tool_recall": per_tool,
        "gap_total": int(gap_total),
        "gap_filtered_out": int(gap_filtered_out),
    }

    # Persist
    gt_dir = case_dir / "gt"
    gt_dir.mkdir(parents=True, exist_ok=True)

    out_json = gt_dir / "gt_score.json"
    out_csv = gt_dir / "gt_score.csv"

    write_json(
        out_json,
        {
            "schema_version": "gt_score_v1",
            "summary": summary,
            "rows": rows,
        },
    )
    write_csv(out_csv, rows, fieldnames=list(rows[0].keys()) if rows else [])

    store.add_artifact("gt_score_json", out_json)
    store.add_artifact("gt_score_csv", out_csv)

    # Gap queue outputs
    gap_json = gt_dir / "gt_gap_queue.json"
    gap_csv = gt_dir / "gt_gap_queue.csv"

    gap_payload = {
        "schema_version": "gt_gap_queue_v1",
        "summary": {
            "gt_total": int(total),
            "gap_total": int(gap_total),
            "gap_rate": round(gap_total / total, 6) if total else 0.0,
            "gap_filtered_out": int(gap_filtered_out),
        },
        "rows": gap_rows,
    }
    write_json(gap_json, gap_payload)
    write_csv(gap_csv, gap_rows, fieldnames=list(gap_rows[0].keys()) if gap_rows else [])

    store.add_artifact("gt_gap_queue_json", gap_json)
    store.add_artifact("gt_gap_queue_csv", gap_csv)

    # Store for downstream stages/exports
    store.put("gt_score_summary", summary)
    store.put("gt_score_rows", rows)
    store.put("gt_items", gt_items)
    store.put("gt_gap_rows", gap_rows)

    return summary


def main(argv: Optional[List[str]] = None) -> None:  # pragma: no cover
    """Standalone runner (debug)."""
    ap = argparse.ArgumentParser(description="Run gt_score stage against a suite case analysis dir")
    ap.add_argument("analysis_dir", help="Path to <case_dir>/analysis")
    ap.add_argument("--repo-name", required=True)
    ap.add_argument("--tools", default="semgrep,snyk,sonar")
    ap.add_argument("--gt-tolerance", type=int, default=0, help="GT match tolerance (lines)")
    args = ap.parse_args(argv)

    tools = [t.strip() for t in str(args.tools).split(",") if t.strip()]

    ctx = AnalysisContext.build(
        repo_name=args.repo_name,
        tools=tools,
        runs_dir=Path(args.analysis_dir).resolve().parent / "tool_runs",
        out_dir=Path(args.analysis_dir).resolve(),
        tolerance=3,
        gt_tolerance=int(args.gt_tolerance),
        mode="security",
        formats=("json", "csv"),
        normalized_paths={},
    )

    store = ArtifactStore()
    summary = stage_gt_score(ctx, store)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
