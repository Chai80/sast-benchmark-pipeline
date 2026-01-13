from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv
from pipeline.analysis.utils.path_norm import normalize_file_path
from pipeline.analysis.utils.signatures import cluster_locations

from ._shared import build_location_items, max_severity, severity_rank


def _find_case_dir(ctx: AnalysisContext) -> Optional[Path]:
    out_dir = Path(ctx.out_dir)
    if out_dir.name == "analysis":
        return out_dir.parent
    return None


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
    # Prefer existing clusters from earlier stages.
    clusters = store.get("location_clusters")
    if not isinstance(clusters, list):
        items = build_location_items(ctx, store)
        clusters = cluster_locations(items, tolerance=int(ctx.tolerance), repo_name=ctx.repo_name)
        store.put("location_clusters", clusters)

    # Optional triage rank (if triage_queue already ran)
    triage_rows = store.get("triage_rows") or []
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

        rows.append(
            {
                "suite_id": ctx.suite_id or "",
                "case_id": ctx.case_id or "",
                "repo_name": ctx.repo_name,

                "cluster_id": cid,
                "file_path": fp,
                "start_line": start,
                "end_line": end,
                "line_span": span,

                "tool_count": int(c.get("tool_count") or 0),
                "tools": ",".join(c.get("tools") or []),
                "total_findings": int(sum(tool_counts.values())),

                "semgrep_count": semgrep_c,
                "snyk_count": snyk_c,
                "sonar_count": sonar_c,
                "aikido_count": aikido_c,
                "other_tool_count": other_c,

                "max_severity": str(max_sev or ""),
                "max_severity_rank": int(max_sev_rank or 0),
                "high_count": int(sev_counts.get("HIGH", 0)),
                "medium_count": int(sev_counts.get("MEDIUM", 0)),
                "low_count": int(sev_counts.get("LOW", 0)),
                "unknown_severity_count": int(sev_counts.get("UNKNOWN", 0)),

                "unique_rule_count": len({str(it.get("rule_id") or "") for it in items if isinstance(it, dict) and it.get("rule_id")}),
                "unique_title_count": len({str(it.get("title") or "") for it in items if isinstance(it, dict) and it.get("title")}),
                "unique_finding_id_count": len({str(it.get("finding_id") or "") for it in items if isinstance(it, dict) and it.get("finding_id")}),

                "triage_rank": int(triage_rank_by_cluster.get(cid, 0) or 0),

                "sample_tool": str(sample.get("tool") or ""),
                "sample_rule_id": str(sample.get("rule_id") or ""),
                "sample_title": str(sample.get("title") or ""),
                "sample_severity": str(sample.get("severity") or ""),

                "gt_overlap": gt_overlap,
                "gt_overlap_count": len(gt_ids),
                "gt_overlap_ids": ";".join(gt_ids),
                "gt_overlap_sets": ";".join(sorted(gt_sets)),
                "gt_overlap_tracks": ";".join(sorted(gt_tracks)),
            }
        )

    out_csv = Path(ctx.out_dir) / "_tables" / "triage_features.csv"
    write_csv(
        out_csv,
        rows,
        fieldnames=[
            "suite_id",
            "case_id",
            "repo_name",
            "cluster_id",
            "file_path",
            "start_line",
            "end_line",
            "line_span",
            "tool_count",
            "tools",
            "total_findings",
            "semgrep_count",
            "snyk_count",
            "sonar_count",
            "aikido_count",
            "other_tool_count",
            "max_severity",
            "max_severity_rank",
            "high_count",
            "medium_count",
            "low_count",
            "unknown_severity_count",
            "unique_rule_count",
            "unique_title_count",
            "unique_finding_id_count",
            "triage_rank",
            "sample_tool",
            "sample_rule_id",
            "sample_title",
            "sample_severity",
            "gt_overlap",
            "gt_overlap_count",
            "gt_overlap_ids",
            "gt_overlap_sets",
            "gt_overlap_tracks",
        ],
    )
    store.add_artifact("triage_features_csv", out_csv)

    return {"rows": len(rows)}
