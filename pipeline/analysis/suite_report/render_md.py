from __future__ import annotations

"""pipeline.analysis.suite_report.render_md

Markdown rendering for suite reports.

This module contains formatting logic only (no file I/O).
"""

from typing import Any, Dict, List, Optional, Sequence


def render_suite_report_markdown(report: Dict[str, Any]) -> str:
    """Render a suite report model as markdown."""

    return _render_markdown(report)


def _fmt_ptr(k: str, p: Optional[str]) -> str:
    if not p:
        return f"- {k}: (missing)"
    return f"- {k}: `{p}`"


def _render_header_lines(
    *, sid: str, created_at: str, generated_at: Any, scanners_requested: Sequence[Any]
) -> List[str]:
    lines: List[str] = []

    lines.append(f"# Suite report: `{sid}`")
    if created_at:
        lines.append(f"- created_at: `{created_at}`")
    lines.append(f"- generated_at: `{generated_at}`")
    if scanners_requested:
        lines.append(f"- scanners_requested: {', '.join([f'`{s}`' for s in scanners_requested])}")
    lines.append("")

    return lines


def _render_execution_summary_lines(
    *,
    cases_total: int,
    cases_ok: int,
    missing_outputs: Sequence[Any],
    no_clusters: Sequence[Any],
    tools_used: Sequence[Any],
    tools_missing: Sequence[Any],
    empty_tool_cases: Dict[str, Any],
    filtered_to_zero_tool_cases: Dict[str, Any],
) -> List[str]:
    lines: List[str] = []

    lines.append("## Execution summary")
    lines.append("")
    lines.append(f"- cases_total: **{cases_total}**")
    lines.append(f"- cases_analyzed_ok: **{cases_ok}**")
    if missing_outputs:
        lines.append(f"- cases_missing_outputs: {', '.join([f'`{c}`' for c in missing_outputs])}")
    if no_clusters:
        lines.append(f"- cases_no_clusters: {', '.join([f'`{c}`' for c in no_clusters])}")
    if tools_used:
        lines.append(f"- tools_used_union: {', '.join([f'`{t}`' for t in tools_used])}")
    if tools_missing:
        lines.append(f"- tools_missing_union: {', '.join([f'`{t}`' for t in tools_missing])}")

    if empty_tool_cases:
        lines.append("")
        lines.append("### Empty tool outputs (raw)")
        for tool, cids in sorted(empty_tool_cases.items()):
            if not cids:
                continue
            lines.append(f"- `{tool}`: {', '.join([f'`{c}`' for c in cids])}")

    if filtered_to_zero_tool_cases:
        lines.append("")
        lines.append("### Tool outputs filtered to zero")
        lines.append(
            "- These tools emitted findings, but 0 survived Durinn filtering (mode + exclude_prefixes/include_harness)."
        )
        for tool, cids in sorted(filtered_to_zero_tool_cases.items()):
            if not cids:
                continue
            lines.append(f"- `{tool}`: {', '.join([f'`{c}`' for c in cids])}")

    return lines


def _render_action_items_lines(action_items: Sequence[Any]) -> List[str]:
    if not action_items:
        return []

    lines: List[str] = []
    lines.append("")
    lines.append("## Action items")
    lines.append("")
    for a in action_items:
        lines.append(f"- {a}")

    return lines


def _render_results_highlights_lines(
    top_gap_cases: Sequence[Any], top_sev_cases: Sequence[Any]
) -> List[str]:
    lines: List[str] = []

    # Results highlights (always present)
    lines.append("")
    lines.append("## Results highlights")
    lines.append("")

    if top_gap_cases:
        lines.append("### Top GT gap cases")
        lines.append("")
        for r in top_gap_cases:
            if not isinstance(r, dict):
                continue
            cid = r.get("case_id")
            gap_total = r.get("gap_total")
            score = r.get("gt_score_json")
            gapq = r.get("gt_gap_queue_csv")
            lines.append(
                f"- `{cid}`: gap_total={gap_total} | gt_score: `{score}` | gt_gap_queue: `{gapq}`"
            )

    if top_sev_cases:
        lines.append("")
        lines.append("### Top severity cases")
        lines.append("")
        for r in top_sev_cases:
            if not isinstance(r, dict):
                continue
            cid = r.get("case_id")
            sev = r.get("top_severity")
            tri = r.get("triage_rows")
            tq = r.get("triage_queue_csv")
            hp = r.get("hotspot_pack_json")
            lines.append(
                f"- `{cid}`: top_severity={sev} triage_rows={tri} | triage_queue: `{tq}` | hotspot_pack: `{hp}`"
            )

    return lines


def _render_triage_eval_macro_lines(macro: Dict[str, Any]) -> List[str]:
    if not macro:
        return []

    lines: List[str] = []

    lines.append("")
    lines.append("## Triage eval (macro)")
    lines.append("")
    lines.append("| strategy | k | precision | gt_coverage |")
    lines.append("|---|---:|---:|---:|")

    for strat, by_k in macro.items():
        if not isinstance(by_k, dict):
            continue
        for k, vals in by_k.items():
            if not isinstance(vals, dict):
                continue
            p = vals.get("precision")
            c = vals.get("gt_coverage")
            lines.append(
                f"| `{strat}` | {k} | {p:.3f} | {c:.3f} |"
                if isinstance(p, float) and isinstance(c, float)
                else f"| `{strat}` | {k} | {p} | {c} |"
            )

    return lines


def _render_calibration_support_lines(
    *,
    min_support_by_owasp: Any,
    owasp_support: Dict[str, Any],
    owasp_fallback: Sequence[Any],
) -> List[str]:
    if not owasp_support:
        return []

    lines: List[str] = []

    lines.append("")
    lines.append("## Calibration support")
    lines.append("")
    if isinstance(min_support_by_owasp, int):
        lines.append(f"- min_support_by_owasp: `{min_support_by_owasp}`")
    if owasp_fallback:
        lines.append(f"- owasp_fallback: {', '.join([f'`{x}`' for x in owasp_fallback])}")
    lines.append("")
    lines.append("| OWASP | cases | clusters | gt_positive_clusters |")
    lines.append("|---|---:|---:|---:|")
    for owasp, v in sorted(owasp_support.items()):
        if not isinstance(v, dict):
            continue
        lines.append(
            f"| `{owasp}` | {int(v.get('cases') or 0)} | {int(v.get('clusters') or 0)} | {int(v.get('gt_positive_clusters') or 0)} |"
        )

    return lines


def _render_qa_lines(
    *, qa_scope: Any, qa_no_reanalyze: Any, qa_result: Dict[str, Any]
) -> List[str]:
    lines: List[str] = []

    lines.append("")
    lines.append("## QA")
    lines.append("")
    if qa_scope:
        lines.append(f"- scope: `{qa_scope}`")
    if qa_no_reanalyze is not None:
        lines.append(f"- no_reanalyze: `{qa_no_reanalyze}`")
    if qa_result:
        status = qa_result.get("status")
        if status:
            lines.append(f"- status: `{status}`")

    return lines


def _render_pointers_lines(suite_tables: Dict[str, Any]) -> List[str]:
    lines: List[str] = []

    lines.append("")
    lines.append("## Where to click")
    lines.append("")

    for k in sorted(suite_tables.keys()):
        v = suite_tables.get(k)
        if not isinstance(v, str) and v is not None:
            v = str(v)
        lines.append(_fmt_ptr(k, v if isinstance(v, str) else None))

    return lines


def _render_integrity_notes_lines(integrity: Dict[str, Any]) -> List[str]:
    if not integrity:
        return []

    notes = integrity.get("gt_ambiguity") if isinstance(integrity.get("gt_ambiguity"), dict) else {}
    if not notes:
        return []

    lines: List[str] = []

    lines.append("")
    lines.append("## Integrity notes")
    lines.append("")
    evidence = integrity.get("evidence")
    if evidence:
        lines.append(f"- evidence: `{evidence}`")

    items: List[str] = []
    for k in [
        "clusters_total",
        "gt_ids_covered",
        "many_to_one_clusters",
        "one_to_many_gt_ids",
        "max_gt_ids_per_cluster",
        "max_clusters_per_gt_id",
    ]:
        if k in notes and notes.get(k) is not None:
            items.append(f"{k}={notes.get(k)}")

    if items:
        lines.append("- " + ", ".join(items))

    warnings = integrity.get("warnings") if isinstance(integrity.get("warnings"), list) else []
    if warnings:
        lines.append(f"- warnings: {', '.join([str(w) for w in warnings if str(w).strip()])}")

    return lines


def _render_markdown(report: Dict[str, Any]) -> str:
    suite = report.get("suite") if isinstance(report.get("suite"), dict) else {}
    plan = report.get("plan") if isinstance(report.get("plan"), dict) else {}
    exec_ = report.get("execution") if isinstance(report.get("execution"), dict) else {}
    triage_eval = report.get("triage_eval") if isinstance(report.get("triage_eval"), dict) else {}
    calibration = report.get("calibration") if isinstance(report.get("calibration"), dict) else {}
    qa = report.get("qa") if isinstance(report.get("qa"), dict) else {}
    pointers = report.get("pointers") if isinstance(report.get("pointers"), dict) else {}
    action_items = (
        report.get("action_items") if isinstance(report.get("action_items"), list) else []
    )

    sid = suite.get("suite_id") or ""
    created_at = suite.get("created_at") or ""

    scanners_requested = plan.get("scanners_requested") or []

    cases_total = int(exec_.get("cases_total") or 0)
    cases_ok = int(exec_.get("cases_analyzed_ok") or 0)
    missing_outputs = exec_.get("cases_missing_outputs") or []
    no_clusters = exec_.get("cases_no_clusters") or []
    tools_used = exec_.get("tools_used_union") or []
    tools_missing = exec_.get("tools_missing_union") or []
    empty_tool_cases = exec_.get("empty_tool_cases") or {}
    filtered_to_zero_tool_cases = exec_.get("filtered_to_zero_tool_cases") or {}

    macro = triage_eval.get("macro") if isinstance(triage_eval.get("macro"), dict) else {}

    min_support_by_owasp = calibration.get("min_support_by_owasp")
    owasp_support = (
        calibration.get("owasp_support")
        if isinstance(calibration.get("owasp_support"), dict)
        else {}
    )
    owasp_fallback = (
        calibration.get("owasp_fallback")
        if isinstance(calibration.get("owasp_fallback"), list)
        else []
    )

    qa_scope = qa.get("scope")
    qa_no_reanalyze = qa.get("no_reanalyze")
    qa_result = qa.get("result") if isinstance(qa.get("result"), dict) else {}

    top_gap_cases = (
        pointers.get("top_gt_gap_cases")
        if isinstance(pointers.get("top_gt_gap_cases"), list)
        else []
    )
    top_sev_cases = (
        pointers.get("top_severity_cases")
        if isinstance(pointers.get("top_severity_cases"), list)
        else []
    )
    suite_tables = (
        pointers.get("suite_tables") if isinstance(pointers.get("suite_tables"), dict) else {}
    )

    integrity = report.get("integrity") if isinstance(report.get("integrity"), dict) else {}

    lines: List[str] = []

    lines.extend(
        _render_header_lines(
            sid=str(sid),
            created_at=str(created_at),
            generated_at=report.get("generated_at"),
            scanners_requested=scanners_requested,
        )
    )

    lines.extend(
        _render_execution_summary_lines(
            cases_total=cases_total,
            cases_ok=cases_ok,
            missing_outputs=missing_outputs,
            no_clusters=no_clusters,
            tools_used=tools_used,
            tools_missing=tools_missing,
            empty_tool_cases=empty_tool_cases,
            filtered_to_zero_tool_cases=filtered_to_zero_tool_cases,
        )
    )

    if action_items:
        lines.extend(_render_action_items_lines(action_items))

    lines.extend(_render_results_highlights_lines(top_gap_cases, top_sev_cases))

    lines.extend(_render_triage_eval_macro_lines(macro))

    lines.extend(
        _render_calibration_support_lines(
            min_support_by_owasp=min_support_by_owasp,
            owasp_support=owasp_support,
            owasp_fallback=owasp_fallback,
        )
    )

    lines.extend(
        _render_qa_lines(qa_scope=qa_scope, qa_no_reanalyze=qa_no_reanalyze, qa_result=qa_result)
    )

    lines.extend(_render_pointers_lines(suite_tables))

    lines.extend(_render_integrity_notes_lines(integrity))

    lines.append("")
    return "\n".join(lines) + "\n"
