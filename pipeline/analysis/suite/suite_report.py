from __future__ import annotations

"""pipeline.analysis.suite_report

Generate a human-friendly, suite-level report summarizing:
- execution health (missing tools / missing runs / empty cases)
- per-case signal (clusters, triage queue size, GT match rate)
- calibration impact (Precision@K / Coverage@K deltas)
- pointers to the most useful artifacts

This module is intentionally read-only: it consumes existing suite artifacts
and produces:
- runs/suites/<suite_id>/analysis/suite_report.md
- runs/suites/<suite_id>/analysis/suite_report.json
"""

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CaseRow:
    case_id: str
    tools_used: List[str]
    tools_missing: List[str]
    clusters: int
    triage_rows: int
    gt_matched: int
    gt_total: int
    match_rate: Optional[float]
    gap_total: Optional[int]
    top_severity: Optional[str]
    warnings: List[str]
    # relative pointers
    analysis_manifest: str
    triage_queue_csv: Optional[str]
    triage_queue_json: Optional[str]
    gt_score_json: Optional[str]
    gt_gap_queue_csv: Optional[str]
    hotspot_pack_json: Optional[str]
    # tool findings counts (best-effort)
    tool_findings: Dict[str, Optional[int]]


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


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


def _compute_macro_from_topk_rows(
    topk_rows: List[Dict[str, Any]],
    *,
    ks: Sequence[int] = (10, 25, 50),
    strategies: Sequence[str] = ("baseline", "agreement", "calibrated_global", "calibrated"),
) -> Dict[str, Dict[str, Dict[str, float]]]:
    """Compute macro Precision@K and Coverage@K from triage_eval_topk rows.

    Returns:
      metrics[strategy][str(k)] = {"precision": x, "gt_coverage": y}
    """

    # Group rows by (case_id, strategy)
    by_case: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for r in topk_rows:
        cid = str(r.get("case_id") or "")
        strat = str(r.get("strategy") or "")
        if not cid or not strat:
            continue
        by_case.setdefault((cid, strat), []).append(r)

    # Sort each list by rank
    for key, rows in by_case.items():
        rows.sort(key=lambda rr: int(rr.get("rank") or 0))

    out: Dict[str, Dict[str, Dict[str, float]]] = {s: {} for s in strategies}

    for strat in strategies:
        for k in ks:
            precisions: List[float] = []
            coverages: List[float] = []
            for (cid, s), rows in by_case.items():
                if s != strat:
                    continue
                n_clusters = len(rows)
                denom = min(int(k), int(n_clusters))
                # Precision@K: tp / denom over cases with denom>0
                if denom > 0:
                    tp = 0
                    for rr in rows[:denom]:
                        try:
                            tp += int(rr.get("gt_overlap") or 0)
                        except Exception:
                            tp += 0
                    precisions.append(tp / float(denom))

                # Coverage@K: gt_covered_at_k / gt_total over cases with gt_total>0
                gt_total = 0
                try:
                    gt_total = int(rows[0].get("gt_total") or 0)
                except Exception:
                    gt_total = 0

                if gt_total > 0:
                    if denom == 0:
                        coverages.append(0.0)
                    else:
                        # row at denom-1 has cumulative_gt_covered
                        rr = rows[denom - 1]
                        try:
                            covered = int(rr.get("cumulative_gt_covered") or 0)
                        except Exception:
                            covered = 0
                        coverages.append(covered / float(gt_total))

            out[strat][str(k)] = {
                "precision": float(sum(precisions) / len(precisions)) if precisions else float("nan"),
                "gt_coverage": float(sum(coverages) / len(coverages)) if coverages else float("nan"),
            }

    return out


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------


def build_suite_report(
    *,
    suite_dir: Path,
    suite_id: Optional[str] = None,
    out_dirname: str = "analysis",
) -> Dict[str, Any]:
    suite_dir = Path(suite_dir).resolve()
    sid = str(suite_id) if suite_id else suite_dir.name
    analysis_dir = suite_dir / out_dirname
    out_tables = analysis_dir / "_tables"

    suite = _safe_read_json(suite_dir / "suite.json") or {}
    plan = suite.get("plan") if isinstance(suite.get("plan"), dict) else {}

    scanners_requested: List[str] = []
    if isinstance(plan.get("scanners"), list):
        scanners_requested = [str(x) for x in plan.get("scanners") if x]
    elif isinstance(suite.get("scanners"), list):
        scanners_requested = [str(x) for x in suite.get("scanners") if x]

    # QA inputs (if present)
    qa_manifest = _safe_read_json(analysis_dir / "qa_manifest.json") or {}
    qa_inputs = qa_manifest.get("inputs") if isinstance(qa_manifest.get("inputs"), dict) else {}
    qa_cfg = qa_inputs.get("qa") if isinstance(qa_inputs.get("qa"), dict) else {}
    qa_scope = qa_cfg.get("scope")
    qa_no_reanalyze = qa_cfg.get("no_reanalyze")

    qa_cal_manifest = _safe_read_json(analysis_dir / "qa_calibration_manifest.json") or {}
    qa_result = qa_cal_manifest.get("result") if isinstance(qa_cal_manifest.get("result"), dict) else {}

    # Calibration artifacts (if present)
    triage_cal = _safe_read_json(analysis_dir / "triage_calibration.json") or {}
    min_support_by_owasp = None
    if isinstance(triage_cal, dict):
        scoring = triage_cal.get("scoring") if isinstance(triage_cal.get("scoring"), dict) else {}
        min_support_by_owasp = scoring.get("min_support_by_owasp")

    case_ids = _resolve_suite_case_ids(suite_dir)
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
                    tools_missing=scanners_requested.copy(),
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
                    gt_gap_queue_csv=_rel(case_dir / "gt" / "gt_gap_queue.csv", suite_dir)
                    if (case_dir / "gt" / "gt_gap_queue.csv").exists()
                    else None,
                    hotspot_pack_json=None,
                    tool_findings={},
                )
            )
            continue

        ctx = manifest.get("context") if isinstance(manifest.get("context"), dict) else {}
        cfg = ctx.get("config") if isinstance(ctx.get("config"), dict) else {}
        requested_tools = cfg.get("requested_tools") if isinstance(cfg.get("requested_tools"), list) else scanners_requested
        requested_tools = [str(x) for x in (requested_tools or []) if x]

        normalized_paths = ctx.get("normalized_paths") if isinstance(ctx.get("normalized_paths"), dict) else {}
        tools_present = sorted([str(t) for t in normalized_paths.keys()])
        tools_missing = sorted([t for t in requested_tools if t not in set(tools_present)])

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
        gap_total = None
        try:
            gap_total = int(((gt.get("gap_summary") or {}) if isinstance(gt.get("gap_summary"), dict) else {}).get("gap_total"))
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

        artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), dict) else {}
        triage_queue_csv = artifacts.get("triage_queue_csv")
        triage_queue_json = artifacts.get("triage_queue_json")
        hotspot_pack = artifacts.get("hotspot_drilldown_pack")

        # Convert artifact paths to suite-relative (some manifests store absolute paths)
        def _norm_art_path(p: Optional[str]) -> Optional[str]:
            if not p:
                return None
            pp = _try_resolve_path(p, suite_dir=suite_dir)
            if pp and pp.exists():
                return _rel(pp, suite_dir)
            # If it already looks relative, keep it.
            if not str(p).startswith("/"):
                return str(p)
            return None

        triage_queue_csv_r = _norm_art_path(triage_queue_csv)
        triage_queue_json_r = _norm_art_path(triage_queue_json)
        hotspot_pack_r = _norm_art_path(hotspot_pack)

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
                match_rate=float(match_rate) if isinstance(match_rate, (int, float)) else None,
                gap_total=gap_total,
                top_severity=str(top_sev) if top_sev else None,
                warnings=warnings_short,
                analysis_manifest=_rel(manifest_path, suite_dir),
                triage_queue_csv=triage_queue_csv_r,
                triage_queue_json=triage_queue_json_r,
                gt_score_json=_rel(gt_score_path, suite_dir) if gt_score_path.exists() else None,
                gt_gap_queue_csv=_rel(gt_gap_csv, suite_dir) if gt_gap_csv.exists() else None,
                hotspot_pack_json=hotspot_pack_r,
                tool_findings=tool_findings,
            )
        )

    # Evaluate macro metrics
    topk_rows = _load_topk_csv(suite_dir, out_dirname)
    macro_metrics = None
    if topk_rows:
        macro_metrics = _compute_macro_from_topk_rows(topk_rows)

    # OWASP support counts (from calibration)
    owasp_support: Dict[str, Dict[str, int]] = {}
    owasp_fallback: List[str] = []
    if isinstance(triage_cal, dict):
        by_owasp = triage_cal.get("tool_stats_by_owasp") if isinstance(triage_cal.get("tool_stats_by_owasp"), dict) else {}
        for k, v in by_owasp.items():
            if not isinstance(v, dict):
                continue
            sup = v.get("support") if isinstance(v.get("support"), dict) else {}
            cases_n = int(sup.get("cases") or 0)
            clusters_n = int(sup.get("clusters") or 0)
            gtpos_n = int(sup.get("gt_positive_clusters") or 0)
            owasp_support[str(k)] = {"cases": cases_n, "clusters": clusters_n, "gt_positive_clusters": gtpos_n}
            if isinstance(min_support_by_owasp, int) and clusters_n < min_support_by_owasp:
                owasp_fallback.append(str(k))

    # Executive summary inputs
    created_at = suite.get("created_at") or suite.get("updated_at") or plan.get("provenance", {}).get("created_at") if isinstance(plan.get("provenance"), dict) else None
    scanners_used = sorted(list(tools_used_union))
    scanners_missing = sorted([t for t in scanners_requested if t not in set(scanners_used)])

    # Action items
    action_items: List[str] = []

    if cases_missing_outputs:
        action_items.append(
            f"{len(cases_missing_outputs)} case(s) are missing tool outputs (or are missing at least one requested tool). "
            "Run benchmark for those cases or adjust the requested scanner set."
        )

    if cases_no_clusters:
        # Try to extract a likely reason from the first case with no clusters.
        sample = next((r for r in case_rows if r.case_id in set(cases_no_clusters)), None)
        if sample:
            # Look up include_harness/exclude_prefixes for the sample
            m = _safe_read_json(suite_dir / "cases" / sample.case_id / out_dirname / "analysis_manifest.json") or {}
            ctx = m.get("context") if isinstance(m.get("context"), dict) else {}
            include_harness = ctx.get("include_harness")
            exclude_prefixes = ctx.get("exclude_prefixes") if isinstance(ctx.get("exclude_prefixes"), list) else []
            reason_bits: List[str] = []
            if include_harness is False:
                reason_bits.append("include_harness=false")
            if exclude_prefixes:
                reason_bits.append(f"exclude_prefixes={exclude_prefixes}")
            reason = (" (" + ", ".join(reason_bits) + ")") if reason_bits else ""
            action_items.append(
                f"{len(cases_no_clusters)} case(s) produced 0 clusters after filtering{reason}. "
                "If unexpected, review harness/exclude settings or ensure scanners target the intended files."
            )

    for tool, cids in sorted(empty_tool_cases.items()):
        # Only call out if the tool was requested/present at least somewhere
        if cids:
            examples = ", ".join(cids[:3])
            extra = "" if len(cids) <= 3 else f" (+{len(cids)-3} more)"
            action_items.append(
                f"{tool} produced empty results (0 findings) for {len(cids)} case(s) (e.g., {examples}{extra}). "
                "Check scanner enablement/auth/config for that repo."
            )

    if owasp_fallback and isinstance(min_support_by_owasp, int):
        action_items.append(
            f"Per-OWASP calibration support is below min_support_by_owasp={min_support_by_owasp} for: {', '.join(sorted(owasp_fallback))}. "
            "Those categories may fall back to global weights."
        )

    # Pointers: top cases by GT gap + severity
    top_gap = sorted(
        [r for r in case_rows if isinstance(r.gap_total, int)],
        key=lambda r: int(r.gap_total or 0),
        reverse=True,
    )[:3]

    top_sev = sorted(
        case_rows,
        key=lambda r: (_severity_rank(r.top_severity), r.triage_rows),
        reverse=True,
    )[:3]

    pointers = {
        "suite_tables": {
            "triage_dataset_csv": _rel(out_tables / "triage_dataset.csv", suite_dir) if (out_tables / "triage_dataset.csv").exists() else None,
            "triage_eval_summary_json": _rel(out_tables / "triage_eval_summary.json", suite_dir) if (out_tables / "triage_eval_summary.json").exists() else None,
            "triage_eval_by_case_csv": _rel(out_tables / "triage_eval_by_case.csv", suite_dir) if (out_tables / "triage_eval_by_case.csv").exists() else None,
            "triage_eval_topk_csv": _rel(out_tables / "triage_eval_topk.csv", suite_dir) if (out_tables / "triage_eval_topk.csv").exists() else None,
            "triage_calibration_json": _rel(analysis_dir / "triage_calibration.json", suite_dir) if (analysis_dir / "triage_calibration.json").exists() else None,
            "triage_calibration_report_csv": _rel(out_tables / "triage_calibration_report.csv", suite_dir) if (out_tables / "triage_calibration_report.csv").exists() else None,
            "triage_calibration_report_by_owasp_csv": _rel(out_tables / "triage_calibration_report_by_owasp.csv", suite_dir)
            if (out_tables / "triage_calibration_report_by_owasp.csv").exists()
            else None,
            "triage_eval_log": _rel(analysis_dir / "triage_eval.log", suite_dir) if (analysis_dir / "triage_eval.log").exists() else None,
            "qa_checklist_md": _rel(analysis_dir / "qa_checklist.md", suite_dir) if (analysis_dir / "qa_checklist.md").exists() else None,
            "qa_checklist_json": _rel(analysis_dir / "qa_checklist.json", suite_dir) if (analysis_dir / "qa_checklist.json").exists() else None,
            "qa_calibration_checklist_txt": _rel(analysis_dir / "qa_calibration_checklist.txt", suite_dir)
            if (analysis_dir / "qa_calibration_checklist.txt").exists()
            else None,
            "qa_manifest_json": _rel(analysis_dir / "qa_manifest.json", suite_dir) if (analysis_dir / "qa_manifest.json").exists() else None,
            "qa_calibration_manifest_json": _rel(analysis_dir / "qa_calibration_manifest.json", suite_dir)
            if (analysis_dir / "qa_calibration_manifest.json").exists()
            else None,
        },
        "top_gt_gap_cases": [
            {
                "case_id": r.case_id,
                "gap_total": r.gap_total,
                "gt_score_json": r.gt_score_json,
                "gt_gap_queue_csv": r.gt_gap_queue_csv,
            }
            for r in top_gap
        ],
        "top_severity_cases": [
            {
                "case_id": r.case_id,
                "top_severity": r.top_severity,
                "triage_rows": r.triage_rows,
                "triage_queue_csv": r.triage_queue_csv,
                "hotspot_pack_json": r.hotspot_pack_json,
            }
            for r in top_sev
        ],
    }

    report_json: Dict[str, Any] = {
        "suite_id": sid,
        "generated_at": _now_iso(),
        "suite_dir": str(suite_dir),
        "analysis_dir": str(analysis_dir),
        "created_at": created_at,
        "scanners_requested": scanners_requested,
        "scanners_used": scanners_used,
        "scanners_missing": scanners_missing,
        "cases_total": len(case_ids),
        "cases_analyzed_ok": len(cases_analyzed_ok),
        "cases_no_clusters": cases_no_clusters,
        "cases_missing_tool_outputs": cases_missing_outputs,
        "qa": {
            "qa_manifest_present": bool(qa_manifest),
            "scope": qa_scope,
            "no_reanalyze": qa_no_reanalyze,
            "checklist_pass": qa_result.get("checklist_pass") if isinstance(qa_result, dict) else None,
            "exit_code": qa_result.get("exit_code") if isinstance(qa_result, dict) else None,
        },
        "calibration": {
            "triage_calibration_present": bool(triage_cal),
            "min_support_by_owasp": min_support_by_owasp,
            "owasp_support": owasp_support,
            "owasp_fallback": sorted(owasp_fallback),
        },
        "metrics": {
            "macro_from_topk": macro_metrics,
            "ks": [10, 25, 50],
        },
        "action_items": action_items,
        "pointers": pointers,
        "cases": [asdict(r) for r in case_rows],
    }

    return report_json


def _render_markdown(report: Dict[str, Any]) -> str:
    sid = report.get("suite_id")
    created_at = report.get("created_at")
    scanners_requested = report.get("scanners_requested") or []
    scanners_used = report.get("scanners_used") or []
    scanners_missing = report.get("scanners_missing") or []

    cases_total = int(report.get("cases_total") or 0)
    cases_ok = int(report.get("cases_analyzed_ok") or 0)
    no_clusters = report.get("cases_no_clusters") or []
    missing_outputs = report.get("cases_missing_tool_outputs") or []

    qa = report.get("qa") or {}
    cal = report.get("calibration") or {}
    metrics = report.get("metrics") or {}
    macro = (metrics.get("macro_from_topk") or {}) if isinstance(metrics.get("macro_from_topk"), dict) else {}

    ptr = report.get("pointers") or {}
    suite_tables = ptr.get("suite_tables") or {}
    top_gt_gap_cases = ptr.get("top_gt_gap_cases") or []
    top_severity_cases = ptr.get("top_severity_cases") or []

    lines: List[str] = []
    lines.append(f"# Suite report — {sid}")
    lines.append("")
    lines.append("## Executive summary")
    lines.append("")
    # Keep to ~10 lines (bullets)
    lines.append(f"- suite_id: `{sid}`")
    if created_at:
        lines.append(f"- timestamp: `{created_at}`")
    lines.append(f"- scanners requested: {', '.join(scanners_requested) if scanners_requested else '(unknown)'}")
    lines.append(f"- scanners used: {', '.join(scanners_used) if scanners_used else '(none)'}")
    if scanners_missing:
        lines.append(f"- scanners missing: {', '.join(scanners_missing)}")
    lines.append(f"- cases total: {cases_total}")
    lines.append(f"- cases analyzed successfully: {cases_ok}")
    lines.append(f"- cases with 0 clusters: {len(no_clusters)}")
    if no_clusters:
        lines.append(f"  - {', '.join(no_clusters[:5])}{'…' if len(no_clusters) > 5 else ''}")
    lines.append(f"- cases missing tool outputs / missing tools: {len(missing_outputs)}")
    lines.append(f"- QA calibration: scope={qa.get('scope')}, reanalyze={'no' if qa.get('no_reanalyze') else 'yes'}")
    lines.append("")
    lines.append("## Results highlights")
    lines.append("")
    lines.append("Top GT gap cases (review these first):")
    if not top_gt_gap_cases:
        lines.append("- (none)")
    else:
        for item in top_gt_gap_cases:
            cid = item.get("case_id")
            gap_total = item.get("gap_total")
            parts: List[str] = []
            if item.get("gt_score_json"):
                parts.append(f"gt: `{item.get('gt_score_json')}`")
            if item.get("gt_gap_queue_csv"):
                parts.append(f"gap_queue: `{item.get('gt_gap_queue_csv')}`")
            suffix = (" — " + " ".join(parts)) if parts else ""
            lines.append(f"- `{cid}` gap_total={gap_total}{suffix}")

    lines.append("")
    lines.append("Top severity / hotspot cases:")
    if not top_severity_cases:
        lines.append("- (none)")
    else:
        for item in top_severity_cases:
            cid = item.get("case_id")
            sev = item.get("top_severity")
            triage_rows = item.get("triage_rows")
            parts = []
            if item.get("triage_queue_csv"):
                parts.append(f"triage_csv: `{item.get('triage_queue_csv')}`")
            if item.get("hotspot_pack_json"):
                parts.append(f"hotspots: `{item.get('hotspot_pack_json')}`")
            suffix = (" — " + " ".join(parts)) if parts else ""
            lines.append(f"- `{cid}` top_severity={sev} triage_rows={triage_rows}{suffix}")

    lines.append("")
    lines.append("Where to click (suite-level):")
    click_order = [
        "qa_checklist_md",
        "qa_calibration_checklist_txt",
        "triage_eval_summary_json",
        "triage_eval_topk_csv",
        "triage_dataset_csv",
        "triage_calibration_json",
    ]
    emitted = False
    for k in click_order:
        v = suite_tables.get(k)
        if v:
            lines.append(f"- {k}: `{v}`")
            emitted = True
    if not emitted:
        lines.append("- (no suite-level artifacts found)")

    lines.append("")
    lines.append("## Action items")
    lines.append("")
    action_items = report.get("action_items") or []
    if action_items:
        for a in action_items:
            lines.append(f"- {a}")
    else:
        lines.append("- (none)")

    lines.append("")
    lines.append("## Per-case health and signal")
    lines.append("")
    lines.append("| case_id | tools_used | tools_missing | clusters | triage_rows | GT matched/total | match_rate | warnings | artifacts |")
    lines.append("|---|---|---|---:|---:|---:|---:|---|---|")
    for r in report.get("cases") or []:
        cid = r.get("case_id")
        tools_used = ",".join(r.get("tools_used") or [])
        tools_missing = ",".join(r.get("tools_missing") or [])
        clusters = r.get("clusters") or 0
        triage_rows = r.get("triage_rows") or 0
        gt_matched = r.get("gt_matched") or 0
        gt_total = r.get("gt_total") or 0
        mr = r.get("match_rate")
        mr_s = "" if mr is None else f"{mr:.3f}"
        warns = "; ".join(r.get("warnings") or [])
        # Artifacts: pick 2-3 key paths
        parts = []
        if r.get("triage_queue_csv"):
            parts.append(f"triage_csv: `{r['triage_queue_csv']}`")
        if r.get("gt_score_json"):
            parts.append(f"gt: `{r['gt_score_json']}`")
        if r.get("analysis_manifest"):
            parts.append(f"manifest: `{r['analysis_manifest']}`")
        art = "<br>".join(parts)
        lines.append(
            f"| `{cid}` | {tools_used} | {tools_missing} | {clusters} | {triage_rows} | {gt_matched}/{gt_total} | {mr_s} | {warns} | {art} |"
        )

    lines.append("")
    lines.append("## Calibration and ranking impact")
    lines.append("")
    lines.append("Macro metrics (mean across cases) computed from `analysis/_tables/triage_eval_topk.csv`.")
    lines.append("")
    lines.append("| strategy | Precision@10 | Coverage@10 | Precision@25 | Coverage@25 | Precision@50 | Coverage@50 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for strat in ("baseline", "agreement", "calibrated_global", "calibrated"):
        ks = macro.get(strat) or {}
        def g(k, field):
            v = (ks.get(str(k)) or {}).get(field)
            if v is None:
                return ""
            try:
                if isinstance(v, float) and (v != v):  # NaN
                    return ""
                return f"{float(v):.3f}"
            except Exception:
                return ""
        lines.append(
            f"| {strat} | {g(10,'precision')} | {g(10,'gt_coverage')} | {g(25,'precision')} | {g(25,'gt_coverage')} | {g(50,'precision')} | {g(50,'gt_coverage')} |"
        )

    owasp_support = (cal.get("owasp_support") or {}) if isinstance(cal, dict) else {}
    if owasp_support:
        lines.append("")
        lines.append("Per-OWASP support counts (for calibration):")
        lines.append("")
        lines.append("| OWASP | cases | clusters | gt_positive_clusters | fallback_to_global? |")
        lines.append("|---|---:|---:|---:|---|")
        fallback = set((cal.get("owasp_fallback") or []) if isinstance(cal, dict) else [])
        for k in sorted(owasp_support.keys()):
            s = owasp_support[k]
            fb = "yes" if k in fallback else "no"
            lines.append(f"| {k} | {s.get('cases',0)} | {s.get('clusters',0)} | {s.get('gt_positive_clusters',0)} | {fb} |")

    lines.append("")
    lines.append("## Where to look next")
    lines.append("")
    lines.append("Suite-level tables:")
    for k, v in suite_tables.items():
        if v:
            lines.append(f"- {k}: `{v}`")
    lines.append("")
    lines.append("Top GT gap cases:")
    for item in ptr.get("top_gt_gap_cases") or []:
        lines.append(
            f"- `{item.get('case_id')}` gap_total={item.get('gap_total')} — gt: `{item.get('gt_score_json')}` gap_queue: `{item.get('gt_gap_queue_csv')}`"
        )
    lines.append("")
    lines.append("Top severity cases:")
    for item in ptr.get("top_severity_cases") or []:
        lines.append(
            f"- `{item.get('case_id')}` top_severity={item.get('top_severity')} triage_rows={item.get('triage_rows')} — triage_csv: `{item.get('triage_queue_csv')}` hotspots: `{item.get('hotspot_pack_json')}`"
        )

    lines.append("")
    lines.append("---")
    lines.append("Notes:")
    lines.append("- Case artifacts live under `cases/<case_id>/analysis/`.")
    lines.append("- Suite aggregate artifacts live under `analysis/`.")
    return "\n".join(lines) + "\n"


def write_suite_report(
    *,
    suite_dir: Path,
    suite_id: Optional[str] = None,
    out_dir: Optional[Path] = None,
    out_dirname: str = "analysis",
) -> Dict[str, str]:
    """Write suite_report.md + suite_report.json.

    Returns a small dict with output paths:
      {"out_md": "...", "out_json": "..."}
    """

    suite_dir = Path(suite_dir).resolve()
    sid = str(suite_id) if suite_id else suite_dir.name
    analysis_dir = Path(out_dir).resolve() if out_dir else (suite_dir / out_dirname)

    report = build_suite_report(suite_dir=suite_dir, suite_id=sid, out_dirname=analysis_dir.name)
    md = _render_markdown(report)

    out_md = analysis_dir / "suite_report.md"
    out_json = analysis_dir / "suite_report.json"

    # Write JSON via the shared artifact writer (keeps formatting consistent).
    from pipeline.analysis.io.write_artifacts import write_json

    write_json(out_json, report)

    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(md, encoding="utf-8")

    return {"out_md": str(out_md), "out_json": str(out_json)}
