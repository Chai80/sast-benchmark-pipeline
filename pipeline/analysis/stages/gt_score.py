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

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json
from pipeline.analysis.utils.filters import filter_findings
from pipeline.analysis.utils.path_norm import normalize_file_path
from sast_benchmark.gt.markers import extract_gt_markers

from ._shared import build_location_items, load_normalized_json


def _find_case_dir(ctx: AnalysisContext) -> Optional[Path]:
    out_dir = Path(ctx.out_dir)
    if out_dir.name == "analysis" and out_dir.parent:
        return out_dir.parent
    return None


def _load_case_json(case_dir: Path) -> Dict[str, Any]:
    p = case_dir / "case.json"
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _coerce_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _normalize_gt_item(raw: Mapping[str, Any], *, repo_name: str) -> Optional[Dict[str, Any]]:
    """Normalize a GT row into the internal shape."""
    gt_id = str(raw.get("id") or raw.get("gt_id") or "").strip()

    file_raw = str(raw.get("file") or raw.get("file_path") or "").strip()
    fp = normalize_file_path(file_raw, repo_name=repo_name)
    if not fp:
        return None

    # lines
    start = raw.get("start_line")
    end = raw.get("end_line")
    if start is None:
        start = raw.get("line")
    if start is None:
        start = raw.get("line_number")
    start_i = _coerce_int(start, default=0)

    if end is None:
        end = raw.get("end")
    if end is None:
        end_i = start_i
    else:
        end_i = _coerce_int(end, default=start_i)

    if end_i < start_i:
        start_i, end_i = end_i, start_i

    # defaults
    track = str(raw.get("track") or "unknown").strip().lower() or "unknown"
    set_name = str(raw.get("set") or "unknown").strip() or "unknown"

    if not gt_id:
        gt_id = f"gt:{fp}:{start_i}:{end_i}"

    return {
        **dict(raw),
        "id": gt_id,
        "file": fp,
        "start_line": int(start_i),
        "end_line": int(end_i),
        "track": track,
        "set": set_name,
    }


def _try_load_yaml(path: Path) -> Tuple[Optional[Any], Optional[str]]:
    try:
        import yaml  # type: ignore

        return yaml.safe_load(path.read_text(encoding="utf-8")), None
    except Exception as e:
        return None, str(e)


def _load_gt_catalog_yaml(gt_dir: Path) -> Tuple[Optional[Path], List[Dict[str, Any]], Optional[str]]:
    """Load a YAML GT catalog from gt_catalog.yaml or gt_catalog.yml.

    Returns (path, items, error).
    """
    p = gt_dir / "gt_catalog.yaml"
    if not p.exists():
        p = gt_dir / "gt_catalog.yml"
    if not p.exists():
        return None, [], None

    data, err = _try_load_yaml(p)
    if data is None and err:
        return p, [], err

    # Accept either:
    # - a list of items
    # - {items: [...]} wrapper
    items_raw: Any = data
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        items_raw = data.get("items")

    items: List[Dict[str, Any]] = []
    if isinstance(items_raw, list):
        for row in items_raw:
            if isinstance(row, dict):
                items.append(dict(row))

    return p, items, None


def _load_gt_markers_json(gt_dir: Path) -> List[Dict[str, Any]]:
    p = gt_dir / "gt_markers.json"
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []

    # Accept list directly or {items:[...]}.
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        data = data.get("items")

    items: List[Dict[str, Any]] = []
    if isinstance(data, list):
        for row in data:
            if isinstance(row, dict):
                items.append(dict(row))
    return items


def _extract_markers_from_repo(case_json: Mapping[str, Any]) -> Tuple[Optional[Path], List[Dict[str, Any]]]:
    """Extract DURINN_GT markers by scanning the repo path from case.json."""
    repo_path = None
    try:
        repo_path = (case_json.get("repo") or {}).get("repo_path")
    except Exception:
        repo_path = None

    if not repo_path:
        return None, []

    p = Path(str(repo_path))
    if not p.exists() or not p.is_dir():
        return p, []

    items = extract_gt_markers(p)
    return p, items


def _case_scoring_track(case_json: Mapping[str, Any]) -> Optional[str]:
    # Newer suite manifests nest under case.track
    try:
        case_obj = case_json.get("case")
        if isinstance(case_obj, dict) and case_obj.get("track"):
            return str(case_obj.get("track") or "").strip() or None
    except Exception:
        pass

    # Legacy fallbacks
    track = None
    try:
        track = case_json.get("track") or (case_json.get("tags") or {}).get("track")
    except Exception:
        track = None

    return str(track).strip() if track else None


def _is_excluded_by_prefix(file_path: str, *, repo_name: str, exclude_prefixes: Sequence[str]) -> bool:
    """Copy of the suite scope filter behavior (prefix-based)."""
    if not exclude_prefixes:
        return False

    fp = normalize_file_path(str(file_path or ""), repo_name=repo_name)
    if not fp:
        return False

    # Normalize: repo-relative, no leading slash, no trailing slash.
    fp_n = fp.replace("\\", "/")
    while fp_n.startswith("./"):
        fp_n = fp_n[2:]
    fp_n = fp_n.lstrip("/").rstrip("/")
    while "//" in fp_n:
        fp_n = fp_n.replace("//", "/")

    for raw in exclude_prefixes:
        pfx = str(raw or "").replace("\\", "/")
        while pfx.startswith("./"):
            pfx = pfx[2:]
        pfx = pfx.lstrip("/").rstrip("/")
        while "//" in pfx:
            pfx = pfx.replace("//", "/")
        if not pfx:
            continue
        if fp_n == pfx or fp_n.startswith(pfx + "/"):
            return True

    return False


def _file_presence_from_normalized(
    ctx: AnalysisContext,
    *,
    apply_mode_filter: bool,
    apply_scope_filter: bool,
) -> Dict[str, bool]:
    """Return a dict of file_path -> True for files with any findings."""
    present: Dict[str, bool] = {}

    for tool, norm_path in (ctx.normalized_paths or {}).items():
        data = load_normalized_json(norm_path)
        findings = data.get("findings") or []
        if not isinstance(findings, list):
            continue

        if apply_mode_filter:
            findings = filter_findings(str(tool), findings, mode=ctx.mode)

        for f in findings:
            if not isinstance(f, dict):
                continue
            fp = normalize_file_path(str(f.get("file_path") or ""), repo_name=ctx.repo_name)
            if not fp:
                continue
            if apply_scope_filter and _is_excluded_by_prefix(fp, repo_name=ctx.repo_name, exclude_prefixes=ctx.exclude_prefixes or ()):  # type: ignore[arg-type]
                continue
            present[fp] = True

    return present


def _tool_locations(location_items: Sequence[Mapping[str, Any]]) -> Dict[str, List[Tuple[str, int]]]:
    by_tool: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
    for it in location_items:
        tool = str(it.get("tool") or "").strip()
        fp = str(it.get("file_path") or "").strip()
        ln = _coerce_int(it.get("line_number"), default=0)
        if tool and fp:
            by_tool[tool].append((fp, ln))
    return by_tool


def _match_tools_for_gt(
    *,
    gt_file: str,
    gt_start: int,
    gt_end: int,
    tool_locs: Mapping[str, Sequence[Tuple[str, int]]],
    tol: int,
) -> List[str]:
    matched: List[str] = []
    lo = int(gt_start) - int(tol)
    hi = int(gt_end) + int(tol)
    for tool, locs in tool_locs.items():
        for fp, ln in locs:
            if fp != gt_file:
                continue
            if lo <= int(ln) <= hi:
                matched.append(tool)
                break
    return sorted(set(matched))


@register_stage(
    "gt_score",
    kind="analysis",
    description="Optional GT scoring (markers/YAML) for a suite case.",
)
def stage_gt_score(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    cfg = dict(ctx.config or {})
    gt_source_mode = str(cfg.get("gt_source") or "auto").strip().lower()

    # Normalize synonyms
    if gt_source_mode in ("off", "none", "disable", "disabled"):
        gt_source_mode = "none"

    if gt_source_mode not in ("auto", "markers", "yaml", "none"):
        store.add_warning(f"gt_score: unknown gt_source={gt_source_mode!r}; using 'auto'")
        gt_source_mode = "auto"

    if gt_source_mode == "none":
        return {"status": "skipped", "reason": "gt_disabled", "gt_source_mode": gt_source_mode}

    case_dir = _find_case_dir(ctx)
    if not case_dir:
        return {"status": "skipped", "reason": "not_suite_layout", "gt_source_mode": gt_source_mode}

    gt_dir = case_dir / "gt"
    case_json = _load_case_json(case_dir)
    scoring_track = _case_scoring_track(case_json)
    scoring_track_n = scoring_track.strip().lower() if scoring_track else None

    # --- Choose GT source -------------------------------------------------
    gt_source_used: Optional[str] = None
    raw_items: List[Dict[str, Any]] = []
    gt_catalog_path: Optional[Path] = None

    if gt_source_mode == "yaml":
        gt_catalog_path, raw_items, err = _load_gt_catalog_yaml(gt_dir)
        if gt_catalog_path is None:
            # required in yaml mode
            return {"status": "skipped", "reason": "no_gt_catalog_yaml", "gt_source_mode": "yaml"}
        if err:
            return {
                "status": "skipped",
                "reason": "gt_catalog_yaml_error",
                "gt_source_mode": "yaml",
                "gt_catalog_path": str(gt_catalog_path),
                "error": err,
            }
        if not raw_items:
            return {
                "status": "skipped",
                "reason": "empty_gt_catalog_yaml",
                "gt_source_mode": "yaml",
                "gt_catalog_path": str(gt_catalog_path),
            }
        gt_source_used = "yaml"

    elif gt_source_mode in ("auto", "markers"):
        # 1) Captured marker catalog, if present
        raw_items = _load_gt_markers_json(gt_dir)
        if raw_items:
            gt_source_used = "markers"

        # 2) Scan repo for DURINN_GT markers (tests rely on this)
        if not raw_items:
            _repo_path, scanned = _extract_markers_from_repo(case_json)
            raw_items = scanned
            if raw_items:
                gt_source_used = "markers"

        if gt_source_mode == "markers" and not raw_items:
            return {"status": "skipped", "reason": "no_gt_markers", "gt_source_mode": "markers"}

        # 3) YAML fallback (auto only)
        if gt_source_mode == "auto" and not raw_items:
            gt_catalog_path, raw_items, err = _load_gt_catalog_yaml(gt_dir)
            if err:
                return {
                    "status": "skipped",
                    "reason": "gt_catalog_yaml_error",
                    "gt_source_mode": "auto",
                    "gt_catalog_path": str(gt_catalog_path) if gt_catalog_path else None,
                    "error": err,
                }
            if raw_items:
                gt_source_used = "yaml"

        if not raw_items:
            return {"status": "skipped", "reason": "no_gt", "gt_source_mode": gt_source_mode}

    # --- Normalize + filter GT items -------------------------------------
    gt_items: List[Dict[str, Any]] = []
    for row in raw_items:
        if not isinstance(row, dict):
            continue
        norm = _normalize_gt_item(row, repo_name=ctx.repo_name)
        if norm:
            gt_items.append(norm)

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
            return {"status": "skipped", "reason": "no_gt_markers", "gt_source_mode": "markers"}
        return {"status": "skipped", "reason": "no_gt", "gt_source_mode": gt_source_mode}

    filtered_out_by_track = 0
    if scoring_track_n:
        before = len(gt_items)
        gt_items = [it for it in gt_items if str(it.get("track") or "unknown").lower() == scoring_track_n]
        filtered_out_by_track = before - len(gt_items)
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
    tool_locs = _tool_locations(location_items)

    # --- Gap queue file presence (unfiltered vs filtered) ----------------
    files_unfiltered = _file_presence_from_normalized(ctx, apply_mode_filter=False, apply_scope_filter=False)
    files_mode_only = _file_presence_from_normalized(ctx, apply_mode_filter=True, apply_scope_filter=False)
    # fully-filtered file presence can be derived from location_items
    files_full: Dict[str, bool] = {}
    for it in location_items:
        fp = str(it.get("file_path") or "").strip()
        if fp:
            files_full[fp] = True

    # --- Score ------------------------------------------------------------
    gt_tol = int(getattr(ctx, "gt_tolerance", 0) or 0)
    if gt_tol < 0:
        gt_tol = 0

    rows: List[Dict[str, Any]] = []
    per_tool_matched: Counter[str] = Counter()
    by_set_total: Counter[str] = Counter()
    by_set_matched: Counter[str] = Counter()
    by_track_total: Counter[str] = Counter()
    by_track_matched: Counter[str] = Counter()

    matched_gt_items = 0

    for gt in gt_items:
        gt_id = str(gt.get("id") or "")
        gt_file = str(gt.get("file") or "")
        gt_start = _coerce_int(gt.get("start_line"), default=0)
        gt_end = _coerce_int(gt.get("end_line"), default=gt_start)
        gt_track = str(gt.get("track") or "unknown")
        gt_set = str(gt.get("set") or "unknown")

        by_set_total[gt_set] += 1
        by_track_total[gt_track] += 1

        matched_tools = _match_tools_for_gt(
            gt_file=gt_file,
            gt_start=gt_start,
            gt_end=gt_end,
            tool_locs=tool_locs,
            tol=gt_tol,
        )
        matched = bool(matched_tools)
        if matched:
            matched_gt_items += 1
            by_set_matched[gt_set] += 1
            by_track_matched[gt_track] += 1
            for t in matched_tools:
                per_tool_matched[str(t)] += 1

        rows.append(
            {
                "gt_id": gt_id,
                "track": gt_track,
                "set": gt_set,
                "file": gt_file,
                "start_line": gt_start,
                "end_line": gt_end,
                "matched": bool(matched),
                "matched_tool_count": len(matched_tools),
                "matched_tools": ",".join(matched_tools),
            }
        )

    total_gt_items = len(rows)
    tools = list(ctx.tools or ())
    per_tool_recall = {
        str(t): (float(per_tool_matched.get(str(t), 0)) / float(total_gt_items)) if total_gt_items else 0.0
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
        "match_rate": (float(matched_gt_items) / float(total_gt_items)) if total_gt_items else 0.0,
        "per_tool_matched": {str(t): int(per_tool_matched.get(str(t), 0)) for t in tools},
        "per_tool_recall": {k: round(float(v), 6) for k, v in per_tool_recall.items()},
        "by_set": {
            s: {"total": int(by_set_total[s]), "matched": int(by_set_matched[s])} for s in sorted(by_set_total.keys())
        },
        "by_track": {
            tr: {"total": int(by_track_total[tr]), "matched": int(by_track_matched[tr])}
            for tr in sorted(by_track_total.keys())
        },
    }

    # --- Gap queue --------------------------------------------------------
    gap_rows: List[Dict[str, Any]] = []
    gap_counts: Counter[str] = Counter()

    for r in rows:
        if r.get("matched"):
            continue
        fp = str(r.get("file") or "")

        any_unfiltered = bool(files_unfiltered.get(fp))
        any_mode = bool(files_mode_only.get(fp))
        any_full = bool(files_full.get(fp))

        if not any_unfiltered:
            reason = "no_findings"
            filtered_by = ""
        elif not any_full:
            reason = "filtered_out"
            # best-effort attribution
            if not any_mode:
                filtered_by = "mode"
            else:
                filtered_by = "scope"
        else:
            reason = "found_but_not_matched"
            filtered_by = ""

        gap_counts[reason] += 1
        gap_rows.append({**r, "reason": reason, "filtered_by": filtered_by})

    gap_total = len(gap_rows)
    gap_summary = {
        "gt_total": int(total_gt_items),
        "gap_total": int(gap_total),
        "gap_rate": round(float(gap_total) / float(total_gt_items), 6) if total_gt_items else 0.0,
        "by_reason": {k: int(v) for k, v in sorted(gap_counts.items(), key=lambda kv: kv[0])},
    }

    summary["gap_summary"] = gap_summary

    # --- Write outputs ----------------------------------------------------
    gt_dir.mkdir(parents=True, exist_ok=True)

    out_json = gt_dir / "gt_score.json"
    out_csv = gt_dir / "gt_score.csv"
    out_gap_json = gt_dir / "gt_gap_queue.json"
    out_gap_csv = gt_dir / "gt_gap_queue.csv"

    if "json" in (ctx.formats or ("json",)):
        write_json(out_json, {"summary": summary, "rows": rows})
        store.add_artifact("gt_score_json", out_json)

        write_json(
            out_gap_json,
            {
                "schema_version": "gt_gap_queue_v1",
                "summary": gap_summary,
                "rows": gap_rows,
            },
        )
        store.add_artifact("gt_gap_queue_json", out_gap_json)

    if "csv" in (ctx.formats or ("csv",)):
        write_csv(
            out_csv,
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
        store.add_artifact("gt_score_csv", out_csv)

        write_csv(
            out_gap_csv,
            gap_rows,
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

    # Cache for exporters
    store.put("gt_score_summary", summary)
    store.put("gt_score_rows", rows)
    store.put("gt_gap_rows", gap_rows)

    return summary
