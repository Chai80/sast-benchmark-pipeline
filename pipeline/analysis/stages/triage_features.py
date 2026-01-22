from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv
from pipeline.analysis.utils.path_norm import normalize_file_path
from pipeline.analysis.utils.owasp import infer_owasp

from .common.locations import build_location_items, ensure_location_clusters
from .common.severity import max_severity, severity_rank
from .common.store_keys import StoreKeys


# ---------------------------------------------------------------------------
# Public schema (stable contract)
# ---------------------------------------------------------------------------


# IMPORTANT:
# triage_features.csv is used as a dataset table (per case) and as an input to
# suite-level aggregation/calibration.
#
# Treat this column list as a stable contract:
# - prefer additive changes (new columns) over renames/removals
# - keep IDs + label columns stable
# - keep list/dict columns JSON-encoded for safe parsing
TRIAGE_FEATURES_SCHEMA_VERSION: str = "triage_features_v1"


TRIAGE_FEATURES_FIELDNAMES: List[str] = [
    # ---- Stable identifiers (primary key = suite_id + case_id + cluster_id)
    "suite_id",
    "case_id",
    "cluster_id",

    # ---- Provenance / context
    "schema_version",
    "generated_at",
    "repo_name",
    "repo_url",
    "repo_ref",
    "repo_git_commit",
    "repo_git_branch",
    "repo_expected_commit",
    "repo_expected_branch",
    "case_track",
    "case_tags_json",
    "owasp_id",
    "owasp_title",

    # ---- Location (cluster envelope)
    "file_path",
    "start_line",
    "end_line",
    "line_span",

    # ---- Tool participation / agreement
    "tools_json",
    "tools",  # human-readable (comma-delimited); prefer tools_json for parsing
    "tool_count",
    "suite_tool_count",
    "agreement_tool_ratio",
    "tool_counts_json",
    "finding_count",

    # ---- Tool-specific counts (convenience columns)
    "semgrep_count",
    "snyk_count",
    "sonar_count",
    "aikido_count",
    "other_tool_count",

    # ---- Severity
    "max_severity",
    "max_severity_rank",
    "severity_high_count",
    "severity_medium_count",
    "severity_low_count",
    "severity_unknown_count",

    # ---- Diversity within cluster
    "unique_rule_count",
    "unique_title_count",
    "unique_finding_id_count",

    # ---- Optional triage outputs (if triage_queue ran earlier)
    "triage_rank",

    # ---- Sample exemplar (debugging / inspection)
    "sample_tool",
    "sample_rule_id",
    "sample_title",
    "sample_severity",

    # ---- Ground truth labels
    "gt_overlap",
    "gt_overlap_count",
    "gt_overlap_ids_json",
    "gt_overlap_ids",  # human-readable (semicolon-delimited); prefer *_json for parsing
    "gt_overlap_sets_json",
    "gt_overlap_sets",
    "gt_overlap_tracks_json",
    "gt_overlap_tracks",
]


def _find_case_dir(ctx: AnalysisContext) -> Optional[Path]:
    out_dir = Path(ctx.out_dir)
    if out_dir.name == "analysis":
        return out_dir.parent
    return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_case_manifest(ctx: AnalysisContext) -> Dict[str, Any]:
    """Best-effort load <case_dir>/case.json (suite mode manifest).

    This stage should still work in legacy/non-suite layouts where case.json
    does not exist.
    """

    case_dir = _find_case_dir(ctx)
    if not case_dir:
        return {}

    p = case_dir / "case.json"
    if not p.exists():
        return {}

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

    return data if isinstance(data, dict) else {}


def _to_int(x: Any) -> Optional[int]:
    try:
        if x is None:
            return None
        return int(x)
    except Exception:
        return None


def _overlaps(
    a_start: Optional[int],
    a_end: Optional[int],
    b_start: Optional[int],
    b_end: Optional[int],
    *,
    tol: int = 0,
) -> bool:
    if a_start is None or b_start is None:
        return False
    a_end = a_end if a_end is not None else a_start
    b_end = b_end if b_end is not None else b_start
    return (a_start <= (b_end + tol)) and (a_end >= (b_start - tol))


def _load_gt_rows(ctx: AnalysisContext) -> List[Dict[str, Any]]:
    """
    Load GT rows from <case_dir>/gt/gt_score.json if it exists.

    We keep this stage independent of store keys to reduce coupling.
    """
    case_dir = _find_case_dir(ctx)
    if not case_dir:
        return []

    p = case_dir / "gt" / "gt_score.json"
    if not p.exists():
        return []

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []

    if isinstance(data, dict) and isinstance(data.get("rows"), list):
        return [r for r in data["rows"] if isinstance(r, dict)]
    # fallback: if someone writes rows directly
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    return []


def _choose_sample_item(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Deterministic “representative” sample for a cluster:
      severity desc, then tool/rule/title/finding_id for stable tie-break.
    """
    if not items:
        return {}

    def key(it: Dict[str, Any]) -> tuple:
        sev_r = severity_rank(it.get("severity"))
        tool = str(it.get("tool") or "")
        rule = str(it.get("rule_id") or "")
        title = str(it.get("title") or "")
        fid = str(it.get("finding_id") or "")
        ln = _to_int(it.get("line_number")) or 0
        return (-sev_r, tool, rule, title, fid, ln)

    return sorted([it for it in items if isinstance(it, dict)], key=key)[0]


@register_stage(
    "triage_features",
    kind="analysis",
    description="Emit DS-ready cluster-level feature table (analysis/_tables/triage_features.csv).",
)
def stage_triage_features(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    generated_at = _now_iso()

    # Optional provenance from suite manifests.
    case_manifest = _load_case_manifest(ctx)
    repo_obj = case_manifest.get("repo") or {}
    case_obj = case_manifest.get("case") or {}

    repo_url = str(repo_obj.get("repo_url") or "")
    repo_git_commit = str(repo_obj.get("git_commit") or "")
    repo_git_branch = str(repo_obj.get("git_branch") or "")
    repo_expected_commit = str(case_obj.get("expected_commit") or "")
    repo_expected_branch = str(case_obj.get("expected_branch") or "")
    repo_ref = repo_git_commit or repo_expected_commit or repo_git_branch or repo_expected_branch or ""

    case_track = str(
        case_obj.get("track")
        or case_manifest.get("track")
        or ((case_obj.get("tags") or {}) if isinstance(case_obj.get("tags"), dict) else {}).get("track")
        or ""
    )

    raw_tags = case_obj.get("tags") if isinstance(case_obj.get("tags"), dict) else None
    if raw_tags is None and isinstance(case_manifest.get("tags"), dict):
        raw_tags = case_manifest.get("tags")
    tags_json = json.dumps(raw_tags or {}, sort_keys=True)

    # Prefer existing clusters from earlier stages.
    clusters = ensure_location_clusters(ctx, store)

    # Optional triage rank (if triage_queue already ran)
    triage_rows = store.get(StoreKeys.TRIAGE_ROWS) or []
    triage_rank_by_cluster: Dict[str, int] = {}
    if isinstance(triage_rows, list):
        for r in triage_rows:
            if not isinstance(r, dict):
                continue
            cid = str(r.get("cluster_id") or "")
            rk = _to_int(r.get("rank"))
            if cid and rk:
                triage_rank_by_cluster[cid] = int(rk)

    # Load GT rows (if present) and index by file for overlap features.
    gt_rows = _load_gt_rows(ctx)
    gt_by_file: Dict[str, List[Dict[str, Any]]] = {}
    for g in gt_rows:
        fp = normalize_file_path(str(g.get("file") or g.get("file_path") or ""), repo_name=ctx.repo_name)
        if not fp:
            continue
        gt_by_file.setdefault(fp, []).append(g)

    gt_tol = int(getattr(ctx, "gt_tolerance", 0) or 0)

    owasp_id, owasp_title = infer_owasp(ctx.case_id, out_dir=Path(ctx.out_dir))

    suite_tool_count = len(getattr(ctx, "tools", []) or [])

    rows: List[Dict[str, Any]] = []
    for c in clusters:
        if not isinstance(c, dict):
            continue

        cid = str(c.get("cluster_id") or "")
        fp = str(c.get("file_path") or "")
        start = _to_int(c.get("start_line"))
        end = _to_int(c.get("end_line"))
        if start is None:
            start = 0
        if end is None:
            end = 0
        span = (end - start + 1) if (start > 0 and end >= start) else 0

        items = list(c.get("items") or [])
        tool_counts = Counter(str(it.get("tool") or "") for it in items if isinstance(it, dict))

        # Stable tool list for this cluster.
        cluster_tools = [str(t) for t in (c.get("tools") or []) if str(t).strip()]
        cluster_tools = sorted(set(cluster_tools))
        tool_counts_json = json.dumps({k: int(v) for k, v in sorted(tool_counts.items())}, sort_keys=True)

        # severity stats
        sev_counts = Counter()
        for it in items:
            if not isinstance(it, dict):
                continue
            s = str(it.get("severity") or "").upper().strip()
            if s not in ("HIGH", "MEDIUM", "LOW"):
                s = "UNKNOWN"
            sev_counts[s] += 1

        max_sev, max_sev_rank = max_severity(items)

        # stable sample
        sample = _choose_sample_item(items)

        # tool columns (stable-ish across runs)
        semgrep_c = int(tool_counts.get("semgrep", 0))
        snyk_c = int(tool_counts.get("snyk", 0))
        sonar_c = int(tool_counts.get("sonar", 0))
        aikido_c = int(tool_counts.get("aikido", 0))
        other_c = int(sum(v for k, v in tool_counts.items() if k not in ("semgrep", "snyk", "sonar", "aikido")))

        # GT overlap
        gt_ids: List[str] = []
        gt_sets: set[str] = set()
        gt_tracks: set[str] = set()

        for g in gt_by_file.get(fp, []):
            g_start = _to_int(g.get("start_line"))
            g_end = _to_int(g.get("end_line"))
            if _overlaps(start, end, g_start, g_end, tol=gt_tol):
                gid = str(g.get("gt_id") or g.get("id") or "")
                if gid:
                    gt_ids.append(gid)
                gt_sets.add(str(g.get("set") or "unknown"))
                gt_tracks.add(str(g.get("track") or "unknown"))

        gt_ids = sorted(set(gt_ids))
        gt_overlap = 1 if gt_ids else 0

        gt_sets_list = sorted(gt_sets)
        gt_tracks_list = sorted(gt_tracks)

        # Agreement features
        tool_count = int(c.get("tool_count") or 0)
        agreement_tool_ratio = 0.0
        if suite_tool_count > 0:
            agreement_tool_ratio = round(float(tool_count) / float(suite_tool_count), 6)

        rows.append(
            {
                # IDs
                "suite_id": ctx.suite_id or "",
                "case_id": ctx.case_id or "",
                "cluster_id": cid,

                # Provenance
                "schema_version": TRIAGE_FEATURES_SCHEMA_VERSION,
                "generated_at": generated_at,
                "repo_name": ctx.repo_name,
                "repo_url": repo_url,
                "repo_ref": repo_ref,
                "repo_git_commit": repo_git_commit,
                "repo_git_branch": repo_git_branch,
                "repo_expected_commit": repo_expected_commit,
                "repo_expected_branch": repo_expected_branch,
                "case_track": case_track,
                "case_tags_json": tags_json,
                "owasp_id": owasp_id or "",
                "owasp_title": owasp_title or "",

                # Location
                "file_path": fp,
                "start_line": start,
                "end_line": end,
                "line_span": span,

                # Agreement / participation
                "tools_json": json.dumps(cluster_tools),
                "tools": ",".join(cluster_tools),
                "tool_count": tool_count,
                "suite_tool_count": suite_tool_count,
                "agreement_tool_ratio": agreement_tool_ratio,
                "tool_counts_json": tool_counts_json,
                "finding_count": int(sum(tool_counts.values())),

                # Tool-specific counts
                "semgrep_count": semgrep_c,
                "snyk_count": snyk_c,
                "sonar_count": sonar_c,
                "aikido_count": aikido_c,
                "other_tool_count": other_c,

                # Severity
                "max_severity": str(max_sev or ""),
                "max_severity_rank": int(max_sev_rank or 0),
                "severity_high_count": int(sev_counts.get("HIGH", 0)),
                "severity_medium_count": int(sev_counts.get("MEDIUM", 0)),
                "severity_low_count": int(sev_counts.get("LOW", 0)),
                "severity_unknown_count": int(sev_counts.get("UNKNOWN", 0)),

                # Diversity
                "unique_rule_count": len({str(it.get("rule_id") or "") for it in items if isinstance(it, dict) and it.get("rule_id")}),
                "unique_title_count": len({str(it.get("title") or "") for it in items if isinstance(it, dict) and it.get("title")}),
                "unique_finding_id_count": len({str(it.get("finding_id") or "") for it in items if isinstance(it, dict) and it.get("finding_id")}),

                # Triage outputs (optional)
                "triage_rank": int(triage_rank_by_cluster.get(cid, 0) or 0),

                # Sample exemplar
                "sample_tool": str(sample.get("tool") or ""),
                "sample_rule_id": str(sample.get("rule_id") or ""),
                "sample_title": str(sample.get("title") or ""),
                "sample_severity": str(sample.get("severity") or ""),

                # Labels
                "gt_overlap": gt_overlap,
                "gt_overlap_count": len(gt_ids),
                "gt_overlap_ids_json": json.dumps(gt_ids),
                "gt_overlap_ids": ";".join(gt_ids),
                "gt_overlap_sets_json": json.dumps(gt_sets_list),
                "gt_overlap_sets": ";".join(gt_sets_list),
                "gt_overlap_tracks_json": json.dumps(gt_tracks_list),
                "gt_overlap_tracks": ";".join(gt_tracks_list),
            }
        )

    out_csv = Path(ctx.out_dir) / "_tables" / "triage_features.csv"
    write_csv(
        out_csv,
        rows,
        fieldnames=TRIAGE_FEATURES_FIELDNAMES,
    )
    store.add_artifact("triage_features_csv", out_csv)

    return {"rows": len(rows)}

