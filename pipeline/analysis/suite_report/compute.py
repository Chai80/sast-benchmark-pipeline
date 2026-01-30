from __future__ import annotations

"""pipeline.analysis.suite_report.compute

Compute helpers for the suite report.

These functions derive higher-level report sections from loaded inputs.
"""

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .loaders import (
    _collect_case_rows,
    _load_gt_tolerance_integrity,
    _load_topk_csv,
    _rel,
    _safe_read_json,
    _severity_rank,
)
from .model import CaseRow, SuiteReportInputs


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _compute_macro_from_topk_rows(
    topk_rows: List[Dict[str, Any]],
    *,
    ks: Sequence[int] = (10, 25, 50),
    strategies: Sequence[str] = (
        "baseline",
        "agreement",
        "calibrated_global",
        "calibrated",
    ),
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
                "precision": float(sum(precisions) / len(precisions))
                if precisions
                else float("nan"),
                "gt_coverage": float(sum(coverages) / len(coverages))
                if coverages
                else float("nan"),
            }

    return out


def _compute_owasp_support(
    *,
    triage_cal: Dict[str, Any],
    min_support_by_owasp: Optional[int],
) -> Tuple[Dict[str, Dict[str, int]], List[str]]:
    owasp_support: Dict[str, Dict[str, int]] = {}
    owasp_fallback: List[str] = []

    by_owasp = (
        triage_cal.get("tool_stats_by_owasp")
        if isinstance(triage_cal.get("tool_stats_by_owasp"), dict)
        else {}
    )
    for k, v in by_owasp.items():
        if not isinstance(v, dict):
            continue
        sup = v.get("support") if isinstance(v.get("support"), dict) else {}
        cases_n = int(sup.get("cases") or 0)
        clusters_n = int(sup.get("clusters") or 0)
        gtpos_n = int(sup.get("gt_positive_clusters") or 0)
        owasp_support[str(k)] = {
            "cases": cases_n,
            "clusters": clusters_n,
            "gt_positive_clusters": gtpos_n,
        }
        if isinstance(min_support_by_owasp, int) and clusters_n < min_support_by_owasp:
            owasp_fallback.append(str(k))

    return owasp_support, owasp_fallback


def _resolve_created_at(*, suite: Dict[str, Any], plan: Dict[str, Any]) -> Optional[str]:
    created_at = suite.get("created_at") or suite.get("updated_at")
    if created_at:
        return str(created_at)

    prov = plan.get("provenance") if isinstance(plan.get("provenance"), dict) else {}
    ca = prov.get("created_at")
    return str(ca) if ca else None


def _build_action_items(
    *,
    suite_dir: Path,
    out_dirname: str,
    cases_missing_outputs: Sequence[str],
    cases_no_clusters: Sequence[str],
    empty_tool_cases: Dict[str, List[str]],
    filtered_to_zero_tool_cases: Dict[str, List[str]],
    min_support_by_owasp: Optional[int],
    owasp_fallback: Sequence[str],
    case_rows: Sequence[CaseRow],
) -> List[str]:
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
            m = (
                _safe_read_json(
                    Path(suite_dir)
                    / "cases"
                    / sample.case_id
                    / out_dirname
                    / "analysis_manifest.json"
                )
                or {}
            )
            ctx = m.get("context") if isinstance(m.get("context"), dict) else {}
            include_harness = ctx.get("include_harness")
            exclude_prefixes = (
                ctx.get("exclude_prefixes") if isinstance(ctx.get("exclude_prefixes"), list) else []
            )
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
        if cids:
            examples = ", ".join(cids[:3])
            extra = "" if len(cids) <= 3 else f" (+{len(cids)-3} more)"
            action_items.append(
                f"{tool} produced empty results (0 findings) for {len(cids)} case(s) (e.g., {examples}{extra}). "
                "Check scanner enablement/auth/config for that repo."
            )

    for tool, cids in sorted(filtered_to_zero_tool_cases.items()):
        if cids:
            examples = ", ".join(cids[:3])
            extra = "" if len(cids) <= 3 else f" (+{len(cids)-3} more)"
            action_items.append(
                f"{tool} produced findings, but 0 survived filtering for {len(cids)} case(s) (e.g., {examples}{extra}). "
                "This usually means findings landed only in excluded paths (e.g., benchmark/ harness) or were filtered by mode."
            )

    if owasp_fallback and isinstance(min_support_by_owasp, int):
        action_items.append(
            f"Per-OWASP calibration support is below min_support_by_owasp={min_support_by_owasp} for: {', '.join(sorted(owasp_fallback))}. "
            "Those categories may fall back to global weights."
        )

    return action_items


def _existing_rel(path: Path, *, suite_dir: Path) -> Optional[str]:
    return _rel(path, suite_dir) if Path(path).exists() else None


def _build_pointers(
    *,
    suite_dir: Path,
    analysis_dir: Path,
    out_tables: Path,
    case_rows: Sequence[CaseRow],
) -> Dict[str, Any]:
    # Pointers: top cases by GT gap + severity
    top_gap = sorted(
        [r for r in case_rows if isinstance(r.gap_total, int)],
        key=lambda r: int(r.gap_total or 0),
        reverse=True,
    )[:3]

    top_sev = sorted(
        list(case_rows),
        key=lambda r: (_severity_rank(r.top_severity), r.triage_rows),
        reverse=True,
    )[:3]

    suite_tables = {
        "triage_dataset_csv": _existing_rel(out_tables / "triage_dataset.csv", suite_dir=suite_dir),
        "triage_eval_summary_json": _existing_rel(
            out_tables / "triage_eval_summary.json", suite_dir=suite_dir
        ),
        "triage_eval_by_case_csv": _existing_rel(
            out_tables / "triage_eval_by_case.csv", suite_dir=suite_dir
        ),
        "triage_eval_topk_csv": _existing_rel(
            out_tables / "triage_eval_topk.csv", suite_dir=suite_dir
        ),
        "triage_eval_deltas_by_case_csv": _existing_rel(
            out_tables / "triage_eval_deltas_by_case.csv", suite_dir=suite_dir
        ),
        "triage_tool_utility_csv": _existing_rel(
            out_tables / "triage_tool_utility.csv", suite_dir=suite_dir
        ),
        "triage_tool_marginal_csv": _existing_rel(
            out_tables / "triage_tool_marginal.csv", suite_dir=suite_dir
        ),
        "triage_calibration_json": _existing_rel(
            analysis_dir / "triage_calibration.json", suite_dir=suite_dir
        ),
        "triage_calibration_report_csv": _existing_rel(
            out_tables / "triage_calibration_report.csv", suite_dir=suite_dir
        ),
        "triage_calibration_report_by_owasp_csv": _existing_rel(
            out_tables / "triage_calibration_report_by_owasp.csv", suite_dir=suite_dir
        ),
        "triage_eval_log": _existing_rel(analysis_dir / "triage_eval.log", suite_dir=suite_dir),
        "triage_eval_readme": _existing_rel(
            analysis_dir / "README_triage_eval.md", suite_dir=suite_dir
        ),
        "qa_checklist_md": _existing_rel(analysis_dir / "qa_checklist.md", suite_dir=suite_dir),
        "qa_checklist_json": _existing_rel(analysis_dir / "qa_checklist.json", suite_dir=suite_dir),
        "qa_calibration_checklist_txt": _existing_rel(
            analysis_dir / "qa_calibration_checklist.txt", suite_dir=suite_dir
        ),
        "qa_manifest_json": _existing_rel(analysis_dir / "qa_manifest.json", suite_dir=suite_dir),
        "qa_calibration_manifest_json": _existing_rel(
            analysis_dir / "qa_calibration_manifest.json", suite_dir=suite_dir
        ),
        "gt_tolerance_sweep_summary_csv": _existing_rel(
            analysis_dir / "gt_tolerance_sweep_summary.csv", suite_dir=suite_dir
        ),
    }

    return {
        "suite_tables": suite_tables,
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


def build_suite_report_model(inputs: SuiteReportInputs) -> Dict[str, Any]:
    """Build the suite report model (JSON-serializable dict)."""

    suite_dir = inputs.suite_dir
    sid = inputs.suite_id
    analysis_dir = inputs.analysis_dir
    out_tables = inputs.out_tables

    # Per-case scan
    scan = _collect_case_rows(
        suite_dir=suite_dir,
        out_dirname=inputs.out_dirname,
        case_ids=inputs.case_ids,
        scanners_requested=inputs.scanners_requested,
    )

    case_rows = scan.case_rows

    # Load eval context (best-effort)
    # Prefer triage_eval_summary.json (authoritative suite-level macro/micro)
    # but fall back to deriving macro from triage_eval_topk.csv if needed.
    triage_eval_summary = _safe_read_json(out_tables / "triage_eval_summary.json") or {}
    macro: Dict[str, Any] = {}
    micro: Dict[str, Any] = {}
    delta_vs_baseline: Dict[str, Any] = {}

    if isinstance(triage_eval_summary, dict):
        if isinstance(triage_eval_summary.get("macro"), dict):
            macro = triage_eval_summary.get("macro")  # type: ignore[assignment]
        if isinstance(triage_eval_summary.get("micro"), dict):
            micro = triage_eval_summary.get("micro")  # type: ignore[assignment]
        if isinstance(triage_eval_summary.get("delta_vs_baseline"), dict):
            delta_vs_baseline = triage_eval_summary.get("delta_vs_baseline")  # type: ignore[assignment]

    if not macro:
        topk_rows = _load_topk_csv(suite_dir, inputs.out_dirname)
        macro = _compute_macro_from_topk_rows(topk_rows) if topk_rows else {}

    # Calibration context
    triage_cal = inputs.triage_calibration
    min_support_by_owasp = inputs.min_support_by_owasp
    owasp_support, owasp_fallback = _compute_owasp_support(
        triage_cal=triage_cal, min_support_by_owasp=min_support_by_owasp
    )

    # Integrity notes (best-effort)
    integrity = _load_gt_tolerance_integrity(suite_dir=suite_dir, analysis_dir=analysis_dir)

    action_items = _build_action_items(
        suite_dir=suite_dir,
        out_dirname=inputs.out_dirname,
        cases_missing_outputs=scan.cases_missing_outputs,
        cases_no_clusters=scan.cases_no_clusters,
        empty_tool_cases=scan.empty_tool_cases,
        filtered_to_zero_tool_cases=scan.filtered_to_zero_tool_cases,
        min_support_by_owasp=min_support_by_owasp,
        owasp_fallback=owasp_fallback,
        case_rows=case_rows,
    )

    pointers = _build_pointers(
        suite_dir=suite_dir,
        analysis_dir=analysis_dir,
        out_tables=out_tables,
        case_rows=case_rows,
    )

    created_at = _resolve_created_at(suite=inputs.suite, plan=inputs.plan)

    report_json: Dict[str, Any] = {
        "schema_version": "suite_report_v1",
        "generated_at": _now_iso(),
        "suite": {
            "suite_id": sid,
            "suite_dir": str(suite_dir),
            "created_at": created_at,
        },
        "plan": {
            "scanners_requested": inputs.scanners_requested,
        },
        "execution": {
            "cases_total": len(inputs.case_ids),
            "cases_analyzed_ok": len(scan.cases_analyzed_ok),
            "cases_missing_outputs": list(scan.cases_missing_outputs),
            "cases_no_clusters": list(scan.cases_no_clusters),
            "tools_used_union": sorted(list(scan.tools_used_union)),
            "tools_missing_union": sorted(list(scan.tools_missing_union)),
            "empty_tool_cases": {k: list(v) for k, v in scan.empty_tool_cases.items()},
            "filtered_to_zero_tool_cases": {
                k: list(v) for k, v in scan.filtered_to_zero_tool_cases.items()
            },
        },
        "per_case": [asdict(r) for r in case_rows],
        "triage_eval": {
            "macro": macro,
            "micro": micro,
            "delta_vs_baseline": delta_vs_baseline,
        },
        "calibration": {
            "min_support_by_owasp": min_support_by_owasp,
            "owasp_support": owasp_support,
            "owasp_fallback": sorted(owasp_fallback),
        },
        "qa": {
            "scope": inputs.qa_scope,
            "no_reanalyze": inputs.qa_no_reanalyze,
            "result": inputs.qa_result,
        },
        "integrity": integrity,
        "action_items": action_items,
        "pointers": pointers,
    }

    return report_json
