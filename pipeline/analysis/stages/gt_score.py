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
    # Optional knobs (passed via AnalysisContext.config)
    cfg = dict(ctx.config or {})
    gt_source_opt = str(cfg.get("gt_source") or "auto").strip().lower()
    if gt_source_opt in ("off", "none", "disable", "disabled"):
        return {"status": "skipped", "reason": "gt_disabled", "gt_source": gt_source_opt}
    if gt_source_opt not in ("auto", "markers", "yaml"):
        store.add_warning(f"gt_score: unknown gt_source={gt_source_opt!r}; using 'auto'")
        gt_source_opt = "auto"

    gt_tolerance = 0
    try:
        gt_tolerance = int(cfg.get("gt_tolerance") or 0)
    except Exception:
        gt_tolerance = 0
    if gt_tolerance < 0:
        gt_tolerance = 0

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

    repo_path: Optional[Path] = None
    try:
        rp = (case_json.get("repo") or {}).get("repo_path")
        if rp:
            repo_path = Path(str(rp))
    except Exception:
        repo_path = None

    gt_path: Optional[Path] = None
    gt_items: List[Dict[str, Any]] = []
    gt_source: Optional[str] = None

    # 1) Marker-based GT (preferred when available)
    if gt_source_opt in ("auto", "markers"):
        if repo_path and repo_path.exists() and repo_path.is_dir():
            gt_items = extract_gt_markers(repo_path)
            if gt_items:
                gt_source = "markers"
                out_markers = write_json(
                    gt_dir / "gt_markers.json",
                    {"source": gt_source, "repo_path": str(repo_path), "items": gt_items},
                )
                store.add_artifact("gt_markers_json", out_markers)

    # If the user forced markers and none exist, skip cleanly.
    if gt_source_opt == "markers" and not gt_items:
        store.add_warning("gt_score skipped: gt_source=markers but no GT markers found")
        return {"status": "skipped", "reason": "no_gt_markers", "gt_source": gt_source_opt}

    # 2) YAML gt_catalog fallback (optional or forced)
    if not gt_items and gt_source_opt in ("auto", "yaml"):
        gt_path = _find_gt_catalog(ctx, repo_path=repo_path)
        if gt_path is None:
            # Important: if the user explicitly requested YAML mode, we should
            # *not* silently fall back to other sources.
            if gt_source_opt == "yaml":
                store.add_warning("gt_score skipped: gt_source=yaml but no gt_catalog.yaml found")
                return {"status": "skipped", "reason": "no_gt_catalog", "gt_source": gt_source_opt}

            store.add_warning("gt_score skipped: no GT markers or gt_catalog found")
            return {"status": "skipped", "reason": "no_gt"}

        yaml_mod, yaml_err = _try_import_yaml()
        if yaml_mod is None:
            store.add_warning("gt_score skipped: PyYAML not installed (needed for gt_catalog)")
            return {"status": "skipped", "reason": "pyyaml_not_installed", "error": yaml_err}

        gt_data = yaml_mod.safe_load(gt_path.read_text(encoding="utf-8"))
        gt_items = _parse_gt_items(gt_data)
        gt_source = str(gt_path)

        if gt_source_opt == "yaml" and not gt_items:
            store.add_warning("gt_score skipped: gt_catalog.yaml parsed but contained zero GT items")
            return {"status": "skipped", "reason": "empty_gt_catalog", "gt_source": gt_source_opt, "gt_catalog_path": str(gt_path)}

    # Optional: enforce case-declared track by filtering GT items.
    filtered_out_by_track = 0
    if scoring_track:
        before = len(gt_items)
        gt_items = [
            it
            for it in gt_items
            if str(it.get("track") or "unknown").strip().lower() == scoring_track
        ]
        filtered_out_by_track = before - len(gt_items)
        if filtered_out_by_track:
            store.add_warning(
                f"gt_score: filtered out {filtered_out_by_track} GT items not matching case track={scoring_track!r}"
            )
        if not gt_items:
            store.add_warning(
                f"gt_score skipped: no GT items remained after filtering by case track={scoring_track!r}"
            )
            return {
                "status": "skipped",
                "reason": "no_gt_for_track",
                "track": scoring_track,
                "filtered_out_by_track": filtered_out_by_track,
                "gt_source": gt_source or "unknown",
            }

    # Build location items (FULL filters: mode + scope)
    location_items = build_location_items(ctx, store)
    tool_locs = _tool_locations(location_items)

    rows: List[Dict[str, Any]] = []
    by_set_total: Counter[str] = Counter()
    by_set_matched: Counter[str] = Counter()
    by_track_total: Counter[str] = Counter()
    by_track_matched: Counter[str] = Counter()

    matched_count = 0
    per_tool_matched: Counter[str] = Counter()

    rows: List[Dict[str, Any]] = []
    for gt in gt_items:
        gt_file = str(gt.get("file") or "")
        gt_start = _coerce_int(gt.get("start_line"), default=0)
        gt_end = _coerce_int(gt.get("end_line"), default=gt_start)

        matched_tools = _match_tools_for_gt(
            gt_file=gt_file,
            gt_start=gt_start,
            gt_end=gt_end,
            location_items=location_items,
            repo_name=ctx.repo_name,
            tol=int(gt_tolerance),
        )
        matched = bool(tools)
        if matched:
            matched_count += 1
            by_set_matched[gt_set] += 1
            by_track_matched[gt_track] += 1
            for t in tools:
                per_tool_matched[str(t)] += 1

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
    per_tool_recall = {
        str(t): (per_tool_matched.get(str(t), 0) / total) if total else 0.0 for t in (ctx.tools or [])
    }
    summary: Dict[str, Any] = {
        "status": "ok",
        "gt_source_mode": gt_source_opt,
        "gt_source": gt_source or "unknown",
        "gt_catalog_path": str(gt_path) if gt_path else None,
        "gt_tolerance": int(gt_tolerance),
        "scoring_track": scoring_track,
        "filtered_out_by_track": int(filtered_out_by_track),
        "total_gt_items": total,
        "matched_gt_items": matched_count,
        "match_rate": (matched_count / total) if total else 0.0,
        "per_tool_matched": {str(t): int(per_tool_matched.get(str(t), 0)) for t in (ctx.tools or [])},
        "per_tool_recall": {k: round(float(v), 6) for k, v in per_tool_recall.items()},
        "by_set": {
            s: {"total": int(by_set_total[s]), "matched": int(by_set_matched[s])}
            for s in sorted(by_set_total.keys())
        },
        "by_track": {
            t: {"total": int(by_track_total[t]), "matched": int(by_track_matched[t])}
            for t in sorted(by_track_total.keys())
        },
    }

    # Cache for downstream exporters (e.g. benchmark_pack.json)
    store.put("gt_score_summary", summary)
    store.put("gt_score_rows", rows)

    out_json = write_json(gt_dir / "gt_score.json", {"summary": summary, "rows": rows})
    out_csv = write_csv(
        gt_dir / "gt_score.csv",
        rows,
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
