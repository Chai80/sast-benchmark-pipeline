from __future__ import annotations

"""pipeline.analysis.stages.gt.gap_queue

Build a GT "gap queue": the set of GT items that were NOT matched by any tool,
with best-effort reasons to help triage why.
"""

from collections import Counter
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from pipeline.analysis.framework import AnalysisContext
from pipeline.analysis.utils.filters import filter_findings
from pipeline.analysis.utils.path_norm import normalize_file_path

from ..common.findings import load_normalized_json


def _is_excluded_by_prefix(
    file_path: str, *, repo_name: str, exclude_prefixes: Sequence[str]
) -> bool:
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
            if apply_scope_filter and _is_excluded_by_prefix(
                fp,
                repo_name=ctx.repo_name,
                exclude_prefixes=ctx.exclude_prefixes or (),  # type: ignore[arg-type]
            ):
                continue
            present[fp] = True

    return present


def build_gap_queue(
    ctx: AnalysisContext,
    *,
    rows: Sequence[Mapping[str, Any]],
    location_items: Sequence[Mapping[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Build gap queue rows and summary.

    Parameters
    ----------
    rows:
        Score rows produced by the matcher.
    location_items:
        Filtered prediction locations (reflecting ctx.mode and ctx.exclude_prefixes).
    """

    # --- Gap queue file presence (unfiltered vs filtered) ----------------
    files_unfiltered = _file_presence_from_normalized(
        ctx, apply_mode_filter=False, apply_scope_filter=False
    )
    files_mode_only = _file_presence_from_normalized(
        ctx, apply_mode_filter=True, apply_scope_filter=False
    )

    # fully-filtered file presence can be derived from location_items
    files_full: Dict[str, bool] = {}
    for it in location_items or []:
        fp = str(it.get("file_path") or "").strip()
        if fp:
            files_full[fp] = True

    rows_l: List[Dict[str, Any]] = [dict(r) for r in (rows or [])]
    gap_rows: List[Dict[str, Any]] = []
    gap_counts: Counter[str] = Counter()

    for r in rows_l:
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

    total_gt_items = len(rows_l)
    gap_total = len(gap_rows)
    gap_summary = {
        "gt_total": int(total_gt_items),
        "gap_total": int(gap_total),
        "gap_rate": round(float(gap_total) / float(total_gt_items), 6) if total_gt_items else 0.0,
        "by_reason": {k: int(v) for k, v in sorted(gap_counts.items(), key=lambda kv: kv[0])},
    }

    return gap_rows, gap_summary
