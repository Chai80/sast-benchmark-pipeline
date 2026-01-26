from __future__ import annotations

"""pipeline.analysis.suite_report.loaders

Filesystem-first loaders for suite report generation.

These helpers are intentionally read-only: they consume existing suite artifacts
(suite.json, analysis manifests, aggregate tables) and return structured inputs
for compute/render helpers.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .model import CaseRow, SuiteReportInputs, _CaseScanSummary


def _read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _safe_read_json(path: Path) -> Optional[Any]:
    try:
        if path.exists():
            return _read_json(path)
    except Exception:
        return None
    return None


def _rel(path: Path, base: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path(base).resolve()))
    except Exception:
        return str(path)


def _shorten_warning(w: str, max_len: int = 120) -> str:
    w = (w or "").strip()
    if len(w) <= max_len:
        return w
    return w[: max_len - 1].rstrip() + "…"


def _severity_rank(sev: Optional[str]) -> int:
    # Higher is worse/more urgent
    s = (sev or "").upper()
    return {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }.get(s, 0)


def _stage_summary(manifest: Dict[str, Any], stage_name: str) -> Dict[str, Any]:
    for st in manifest.get("stages", []) or []:
        if st.get("name") == stage_name:
            return st.get("summary") or {}
    return {}


def _resolve_suite_case_ids(suite_dir: Path) -> List[str]:
    suite_json = suite_dir / "suite.json"
    suite = _safe_read_json(suite_json) or {}
    cases = suite.get("cases")

    if isinstance(cases, dict):
        return sorted([str(k) for k in cases.keys()])

    if isinstance(cases, list):
        out: List[str] = []
        for c in cases:
            if isinstance(c, str):
                out.append(c)
            elif isinstance(c, dict):
                cid = c.get("case_id") or c.get("id") or c.get("name")
                if cid:
                    out.append(str(cid))
        return sorted(out)

    # Fallback: directory listing
    cases_dir = suite_dir / "cases"
    if cases_dir.exists():
        return sorted([p.name for p in cases_dir.iterdir() if p.is_dir()])
    return []


def _try_resolve_path(p: str, *, suite_dir: Path) -> Optional[Path]:
    if not p:
        return None
    pp = Path(p)
    if pp.exists():
        return pp

    # Try to map absolute path -> suite-relative path by locating "runs/suites/<suite_id>/".
    s = str(p)
    marker = f"{Path('runs') / 'suites'}"
    # Normalize marker slashes in string
    marker = marker.replace("\\", "/")
    s_norm = s.replace("\\", "/")

    idx = s_norm.find("/runs/suites/")
    if idx != -1:
        tail = s_norm[idx + len("/runs/suites/") :]
        # tail begins with <suite_id>/...
        sid = suite_dir.name
        if tail.startswith(sid + "/"):
            rel_tail = tail[len(sid) + 1 :]
            cand = suite_dir / rel_tail
            if cand.exists():
                return cand

    # Last-resort: if the path contains "cases/<case_id>/..." somewhere, join from suite_dir
    cases_idx = s_norm.find("/cases/")
    if cases_idx != -1:
        rel_tail = s_norm[cases_idx + 1 :]  # strip leading slash
        cand = suite_dir / rel_tail
        if cand.exists():
            return cand

    return None


def _count_normalized_findings(normalized_json_path: Path) -> Optional[int]:
    try:
        data = _read_json(normalized_json_path)
        findings = data.get("findings")
        if isinstance(findings, list):
            return len(findings)
    except Exception:
        return None
    return None


# ---------------------------------------------------------------------------
# Integrity helpers (GT tolerance ambiguity)
# ---------------------------------------------------------------------------


def _to_int(x: Any) -> Optional[int]:
    """Best-effort int parsing; return None on failure."""

    try:
        if x is None:
            return None
        if isinstance(x, bool):
            return int(x)
        return int(float(str(x).strip()))
    except Exception:
        return None


def _read_csv_dict_rows(path: Path) -> List[Dict[str, str]]:
    """Read a small CSV into a list of dict rows (no pandas dependency)."""

    import csv

    with Path(path).open("r", encoding="utf-8", newline="") as f:
        return [dict(r) for r in csv.DictReader(f) if isinstance(r, dict)]


def _load_gt_tolerance_integrity(
    *, suite_dir: Path, analysis_dir: Path
) -> Dict[str, Any]:
    """Load a lightweight ambiguity summary from gt_tolerance_sweep_summary.csv (if present).

    This is read-only and does not change scoring; it's used only to surface potential
    tolerance inflation risks in suite_report output.
    """

    summary_csv = analysis_dir / "gt_tolerance_sweep_summary.csv"
    if not summary_csv.exists():
        return {}

    evidence = _rel(summary_csv, suite_dir)

    try:
        rows = _read_csv_dict_rows(summary_csv)
    except Exception:
        return {
            "evidence": evidence,
            "warnings": ["failed_to_parse_gt_tolerance_sweep_summary"],
        }

    if not rows:
        return {"evidence": evidence, "warnings": ["empty_gt_tolerance_sweep_summary"]}

    # Determine effective tolerance (prefer explicit field, else use gt_tolerance).
    eff_tol: Optional[int] = None
    for r in rows:
        eff_tol = _to_int(r.get("gt_tolerance_effective"))
        if eff_tol is not None:
            break
    if eff_tol is None:
        eff_tol = _to_int(rows[0].get("gt_tolerance"))

    # Choose the row corresponding to eff_tol when possible.
    chosen: Dict[str, str] = dict(rows[0])
    if eff_tol is not None:
        for r in rows:
            t = _to_int(r.get("gt_tolerance"))
            if t is not None and t == eff_tol:
                chosen = dict(r)
                break

    many_to_one = _to_int(chosen.get("many_to_one_clusters")) or 0
    one_to_many = _to_int(chosen.get("one_to_many_gt_ids")) or 0
    max_gt_ids = _to_int(chosen.get("max_gt_ids_per_cluster"))
    max_clusters = _to_int(chosen.get("max_clusters_per_gt_id"))
    clusters_total = _to_int(chosen.get("clusters_total"))

    ambiguity = {
        "clusters_total": clusters_total,
        "gt_ids_covered": _to_int(chosen.get("gt_ids_covered")),
        "many_to_one_clusters": many_to_one,
        "one_to_many_gt_ids": one_to_many,
        "max_gt_ids_per_cluster": max_gt_ids,
        "max_clusters_per_gt_id": max_clusters,
    }

    warnings: List[str] = []
    if many_to_one > 0:
        warnings.append(
            f"many_to_one_clusters={many_to_one} (clusters overlap multiple GT IDs; may inflate TPs)"
        )
    if one_to_many > 0:
        warnings.append(
            f"one_to_many_gt_ids={one_to_many} (GT IDs overlap multiple clusters; may indicate tolerance too large)"
        )
    if max_gt_ids is not None and max_gt_ids > 1:
        warnings.append(f"max_gt_ids_per_cluster={max_gt_ids}")
    if max_clusters is not None and max_clusters > 1:
        warnings.append(f"max_clusters_per_gt_id={max_clusters}")

    return {
        "evidence": evidence,
        "gt_tolerance_effective": eff_tol,
        "tolerance_policy": chosen.get("tolerance_policy") or None,
        "gt_ambiguity": ambiguity,
        "warnings": warnings,
    }


def _load_topk_csv(suite_dir: Path, out_dirname: str) -> Optional[List[Dict[str, Any]]]:
    p = suite_dir / out_dirname / "_tables" / "triage_eval_topk.csv"
    if not p.exists():
        return None
    try:
        import csv

        with p.open("r", encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))
    except Exception:
        return None


def _extract_scanners_requested(
    *, suite: Dict[str, Any], plan: Dict[str, Any]
) -> List[str]:
    scanners_requested: List[str] = []
    if isinstance(plan.get("scanners"), list):
        scanners_requested = [str(x) for x in plan.get("scanners") if x]
    elif isinstance(suite.get("scanners"), list):
        scanners_requested = [str(x) for x in suite.get("scanners") if x]
    return scanners_requested


def load_suite_report_inputs(
    *,
    suite_dir: Path,
    suite_id: Optional[str] = None,
    out_dirname: str = "analysis",
) -> SuiteReportInputs:
    """Load on-disk inputs required to build a suite report model."""

    suite_dir = Path(suite_dir).resolve()
    sid = str(suite_id) if suite_id else suite_dir.name

    analysis_dir = suite_dir / out_dirname
    out_tables = analysis_dir / "_tables"

    suite = _safe_read_json(suite_dir / "suite.json") or {}
    plan = suite.get("plan") if isinstance(suite.get("plan"), dict) else {}

    scanners_requested = _extract_scanners_requested(suite=suite, plan=plan)

    # QA inputs (if present)
    qa_manifest = _safe_read_json(analysis_dir / "qa_manifest.json") or {}
    qa_scope: Optional[str] = None
    qa_no_reanalyze: Optional[bool] = None
    if isinstance(qa_manifest, dict):
        qa_inputs = (
            qa_manifest.get("inputs")
            if isinstance(qa_manifest.get("inputs"), dict)
            else {}
        )
        qa_cfg = qa_inputs.get("qa") if isinstance(qa_inputs.get("qa"), dict) else {}
        qa_scope = qa_cfg.get("scope")
        qa_no_reanalyze = qa_cfg.get("no_reanalyze")

    qa_cal_manifest = (
        _safe_read_json(analysis_dir / "qa_calibration_manifest.json") or {}
    )
    qa_result = (
        qa_cal_manifest.get("result")
        if isinstance(qa_cal_manifest.get("result"), dict)
        else {}
    )

    # Calibration artifacts (if present)
    triage_cal = _safe_read_json(analysis_dir / "triage_calibration.json") or {}
    min_support_by_owasp: Optional[int] = None
    if isinstance(triage_cal, dict):
        scoring = (
            triage_cal.get("scoring")
            if isinstance(triage_cal.get("scoring"), dict)
            else {}
        )
        m = scoring.get("min_support_by_owasp")
        min_support_by_owasp = int(m) if isinstance(m, int) else None

    case_ids = _resolve_suite_case_ids(suite_dir)

    return SuiteReportInputs(
        suite_dir=suite_dir,
        suite_id=sid,
        out_dirname=out_dirname,
        analysis_dir=analysis_dir,
        out_tables=out_tables,
        suite=suite,
        plan=plan,
        scanners_requested=scanners_requested,
        qa_manifest=qa_manifest if isinstance(qa_manifest, dict) else {},
        qa_scope=str(qa_scope) if isinstance(qa_scope, str) else None,
        qa_no_reanalyze=bool(qa_no_reanalyze)
        if isinstance(qa_no_reanalyze, bool)
        else None,
        qa_calibration_manifest=qa_cal_manifest
        if isinstance(qa_cal_manifest, dict)
        else {},
        qa_result=qa_result if isinstance(qa_result, dict) else {},
        triage_calibration=triage_cal if isinstance(triage_cal, dict) else {},
        min_support_by_owasp=min_support_by_owasp,
        case_ids=case_ids,
    )


def _normalize_artifact_path(p: Optional[str], *, suite_dir: Path) -> Optional[str]:
    """Normalize a manifest artifact path to a suite-relative path when possible."""

    if not p:
        return None

    resolved = _try_resolve_path(str(p), suite_dir=suite_dir)
    if resolved and resolved.exists():
        return _rel(resolved, suite_dir)

    # If it already looks relative, keep it.
    if not str(p).startswith("/"):
        return str(p)

    return None


def _collect_case_rows(
    *,
    suite_dir: Path,
    case_ids: Sequence[str],
    out_dirname: str,
    scanners_requested: Sequence[str],
) -> _CaseScanSummary:
    """Load per-case analysis manifests and build CaseRow records."""

    suite_dir = Path(suite_dir).resolve()

    case_rows: List[CaseRow] = []

    tools_used_union: set[str] = set()
    tools_missing_union: set[str] = set()

    cases_missing_outputs: List[str] = []
    cases_no_clusters: List[str] = []
    cases_analyzed_ok: List[str] = []

    # For action items: track tool findings == 0 in any case
    empty_tool_cases: Dict[str, List[str]] = {}

    for cid in case_ids:
        case_dir = suite_dir / "cases" / cid
        manifest_path = case_dir / out_dirname / "analysis_manifest.json"
        manifest = _safe_read_json(manifest_path)

        if not isinstance(manifest, dict):
            cases_missing_outputs.append(cid)
            case_rows.append(
                CaseRow(
                    case_id=cid,
                    tools_used=[],
                    tools_missing=list(scanners_requested),
                    clusters=0,
                    triage_rows=0,
                    gt_matched=0,
                    gt_total=0,
                    match_rate=None,
                    gap_total=None,
                    top_severity=None,
                    warnings=["analysis_manifest.json missing"],
                    analysis_manifest=_rel(manifest_path, suite_dir),
                    triage_queue_csv=None,
                    triage_queue_json=None,
                    gt_score_json=_rel(case_dir / "gt" / "gt_score.json", suite_dir)
                    if (case_dir / "gt" / "gt_score.json").exists()
                    else None,
                    gt_gap_queue_csv=_rel(
                        case_dir / "gt" / "gt_gap_queue.csv", suite_dir
                    )
                    if (case_dir / "gt" / "gt_gap_queue.csv").exists()
                    else None,
                    hotspot_pack_json=None,
                    tool_findings={},
                )
            )
            continue

        ctx = (
            manifest.get("context") if isinstance(manifest.get("context"), dict) else {}
        )
        cfg = ctx.get("config") if isinstance(ctx.get("config"), dict) else {}
        requested_tools = (
            cfg.get("requested_tools")
            if isinstance(cfg.get("requested_tools"), list)
            else list(scanners_requested)
        )
        requested_tools = [str(x) for x in (requested_tools or []) if x]

        normalized_paths = (
            ctx.get("normalized_paths")
            if isinstance(ctx.get("normalized_paths"), dict)
            else {}
        )
        tools_present = sorted([str(t) for t in normalized_paths.keys()])
        tools_missing = sorted(
            [t for t in requested_tools if t not in set(tools_present)]
        )

        tools_used_union.update(tools_present)
        tools_missing_union.update(tools_missing)

        loc = _stage_summary(manifest, "location_matrix")
        tq = _stage_summary(manifest, "triage_queue")
        gt = _stage_summary(manifest, "gt_score")

        clusters = int(loc.get("clusters") or 0)
        triage_rows = int(tq.get("rows") or 0)
        top_sev = tq.get("top_severity")
        gt_total = int(gt.get("total_gt_items") or 0)
        gt_matched = int(gt.get("matched_gt_items") or 0)
        match_rate = gt.get("match_rate")

        gap_total: Optional[int] = None
        try:
            gap_summary = (
                gt.get("gap_summary") if isinstance(gt.get("gap_summary"), dict) else {}
            )
            gap_total = int(gap_summary.get("gap_total"))
        except Exception:
            gap_total = None

        if clusters == 0:
            cases_no_clusters.append(cid)

        # Determine "missing outputs" as: no normalized tools present or any requested tool missing.
        if (len(tools_present) == 0) or (len(tools_missing) > 0):
            cases_missing_outputs.append(cid)

        errors = manifest.get("errors") or []
        if isinstance(errors, list) and len(errors) == 0:
            cases_analyzed_ok.append(cid)

        warnings = [str(w) for w in (manifest.get("warnings") or []) if w]
        warnings_short = [_shorten_warning(w) for w in warnings[:3]]

        artifacts = (
            manifest.get("artifacts")
            if isinstance(manifest.get("artifacts"), dict)
            else {}
        )
        triage_queue_csv = _normalize_artifact_path(
            artifacts.get("triage_queue_csv"), suite_dir=suite_dir
        )
        triage_queue_json = _normalize_artifact_path(
            artifacts.get("triage_queue_json"), suite_dir=suite_dir
        )
        hotspot_pack = _normalize_artifact_path(
            artifacts.get("hotspot_drilldown_pack"), suite_dir=suite_dir
        )

        gt_score_path = case_dir / "gt" / "gt_score.json"
        gt_gap_csv = case_dir / "gt" / "gt_gap_queue.csv"

        # Tool findings counts (best-effort)
        tool_findings: Dict[str, Optional[int]] = {}
        for t, p in normalized_paths.items():
            resolved = _try_resolve_path(str(p), suite_dir=suite_dir)
            if resolved is None:
                tool_findings[str(t)] = None
                continue
            n = _count_normalized_findings(resolved)
            tool_findings[str(t)] = n
            if n == 0:
                empty_tool_cases.setdefault(str(t), []).append(cid)

        case_rows.append(
            CaseRow(
                case_id=cid,
                tools_used=tools_present,
                tools_missing=tools_missing,
                clusters=clusters,
                triage_rows=triage_rows,
                gt_matched=gt_matched,
                gt_total=gt_total,
                match_rate=float(match_rate)
                if isinstance(match_rate, (int, float))
                else None,
                gap_total=gap_total,
                top_severity=str(top_sev) if top_sev else None,
                warnings=warnings_short,
                analysis_manifest=_rel(manifest_path, suite_dir),
                triage_queue_csv=triage_queue_csv,
                triage_queue_json=triage_queue_json,
                gt_score_json=_rel(gt_score_path, suite_dir)
                if gt_score_path.exists()
                else None,
                gt_gap_queue_csv=_rel(gt_gap_csv, suite_dir)
                if gt_gap_csv.exists()
                else None,
                hotspot_pack_json=hotspot_pack,
                tool_findings=tool_findings,
            )
        )

    return _CaseScanSummary(
        case_rows=case_rows,
        tools_used_union=tools_used_union,
        tools_missing_union=tools_missing_union,
        cases_missing_outputs=cases_missing_outputs,
        cases_no_clusters=cases_no_clusters,
        cases_analyzed_ok=cases_analyzed_ok,
        empty_tool_cases=empty_tool_cases,
    )
