from __future__ import annotations

"""pipeline.analysis.suite_report.render_html

HTML rendering for suite reports.

Design goals
------------
- **Single self-contained HTML file** that can be opened directly in a browser.
- **Relative links** that work when the file lives at ``<suite_dir>/<report_dirname>/``.
- **No runtime dependencies** (standard library only).

This renderer intentionally mirrors :mod:`pipeline.analysis.suite_report.render_md`
but adds lightweight visual structure (KPI cards, simple bar glyphs) to make the
suite results easier to skim.
"""

from html import escape
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


def render_suite_report_html(
    report: Dict[str, Any],
    *,
    title: Optional[str] = None,
    base_href: str = "../",
    self_links: Optional[Dict[str, str]] = None,
) -> str:
    """Render a suite report model as a standalone HTML document.

    Parameters
    ----------
    report:
        Suite report model (JSON-serializable dict) produced by
        :func:`pipeline.analysis.suite_report.build_suite_report`.
    title:
        Optional HTML title. Defaults to "Suite report: <suite_id>".
    base_href:
        Base href used for all relative links.

        When the HTML file is written to ``<suite_dir>/<report_dirname>/suite_summary.html``,
        setting ``base_href='../'`` makes links like ``cases/<case_id>/...`` work.
    self_links:
        Optional mapping of friendly link name -> suite-relative path.

        This is useful for linking to sibling report artifacts (e.g. markdown/JSON)
        from within the HTML (especially when a <base href> is set).
    """

    suite = report.get("suite") if isinstance(report.get("suite"), dict) else {}
    plan = report.get("plan") if isinstance(report.get("plan"), dict) else {}
    exec_ = report.get("execution") if isinstance(report.get("execution"), dict) else {}
    triage_eval = report.get("triage_eval") if isinstance(report.get("triage_eval"), dict) else {}
    calibration = report.get("calibration") if isinstance(report.get("calibration"), dict) else {}
    qa = report.get("qa") if isinstance(report.get("qa"), dict) else {}
    pointers = report.get("pointers") if isinstance(report.get("pointers"), dict) else {}
    integrity = report.get("integrity") if isinstance(report.get("integrity"), dict) else {}
    action_items = report.get("action_items") if isinstance(report.get("action_items"), list) else []
    per_case = report.get("per_case") if isinstance(report.get("per_case"), list) else []

    sid = str(suite.get("suite_id") or "")
    created_at = str(suite.get("created_at") or "")
    generated_at = report.get("generated_at")
    scanners_requested = plan.get("scanners_requested") or []

    cases_total = int(exec_.get("cases_total") or 0)
    cases_ok = int(exec_.get("cases_analyzed_ok") or 0)
    cases_missing_outputs = exec_.get("cases_missing_outputs") or []
    cases_no_clusters = exec_.get("cases_no_clusters") or []
    tools_used_union = exec_.get("tools_used_union") or []
    tools_missing_union = exec_.get("tools_missing_union") or []
    empty_tool_cases = exec_.get("empty_tool_cases") or {}
    filtered_to_zero_tool_cases = exec_.get("filtered_to_zero_tool_cases") or {}

    macro = triage_eval.get("macro") if isinstance(triage_eval.get("macro"), dict) else {}
    micro = triage_eval.get("micro") if isinstance(triage_eval.get("micro"), dict) else {}
    delta_vs_baseline = (
        triage_eval.get("delta_vs_baseline")
        if isinstance(triage_eval.get("delta_vs_baseline"), dict)
        else {}
    )

    min_support_by_owasp = calibration.get("min_support_by_owasp")
    owasp_support = calibration.get("owasp_support") if isinstance(calibration.get("owasp_support"), dict) else {}
    owasp_fallback = calibration.get("owasp_fallback") if isinstance(calibration.get("owasp_fallback"), list) else []

    qa_scope = qa.get("scope")
    qa_no_reanalyze = qa.get("no_reanalyze")
    qa_result = qa.get("result") if isinstance(qa.get("result"), dict) else {}

    top_gap_cases = pointers.get("top_gt_gap_cases") if isinstance(pointers.get("top_gt_gap_cases"), list) else []
    top_sev_cases = pointers.get("top_severity_cases") if isinstance(pointers.get("top_severity_cases"), list) else []
    suite_tables = pointers.get("suite_tables") if isinstance(pointers.get("suite_tables"), dict) else {}

    doc_title = title or (f"Suite report: {sid}" if sid else "Suite report")

    parts: List[str] = []
    parts.append("<!doctype html>")
    parts.append("<html lang='en'>")
    parts.append("<head>")
    parts.append("  <meta charset='utf-8'>")
    parts.append("  <meta name='viewport' content='width=device-width,initial-scale=1'>")
    if base_href:
        parts.append(f"  <base href='{escape(base_href, quote=True)}'>")
    parts.append(f"  <title>{escape(doc_title)}</title>")
    parts.append("  <style>")
    parts.append(_CSS)
    parts.append("  </style>")
    parts.append("</head>")
    parts.append("<body>")
    parts.append("<main class='container'>")

    # Header
    parts.append("<header class='header'>")
    parts.append(f"  <h1>Suite report <code>{escape(sid)}</code></h1>")
    parts.append("  <div class='subhead'>")
    if created_at:
        parts.append(f"    <span>created_at: <code>{escape(created_at)}</code></span>")
    parts.append(f"    <span>generated_at: <code>{escape(str(generated_at))}</code></span>")
    if scanners_requested:
        parts.append(
            "    <span>scanners_requested: "
            + ", ".join([f"<code>{escape(str(s))}</code>" for s in scanners_requested])
            + "</span>"
        )
    parts.append("  </div>")
    parts.append("</header>")

    # KPI cards
    parts.append("<section>")
    parts.append("  <h2>At a glance</h2>")
    parts.append("  <div class='kpi-grid'>")
    parts.append(_kpi("Cases total", str(cases_total)))
    parts.append(_kpi("Cases analyzed OK", str(cases_ok)))
    parts.append(_kpi("Missing outputs", str(len(cases_missing_outputs))))
    parts.append(_kpi("No clusters", str(len(cases_no_clusters))))
    parts.append("  </div>")
    parts.append("</section>")

    # Execution summary
    parts.append("<section>")
    parts.append("  <h2>Execution summary</h2>")
    parts.append("  <ul>")
    parts.append(f"    <li>cases_total: <strong>{cases_total}</strong></li>")
    parts.append(f"    <li>cases_analyzed_ok: <strong>{cases_ok}</strong></li>")
    if cases_missing_outputs:
        parts.append(
            "    <li>cases_missing_outputs: "
            + ", ".join([f"<code>{escape(str(c))}</code>" for c in cases_missing_outputs])
            + "</li>"
        )
    if cases_no_clusters:
        parts.append(
            "    <li>cases_no_clusters: "
            + ", ".join([f"<code>{escape(str(c))}</code>" for c in cases_no_clusters])
            + "</li>"
        )
    if tools_used_union:
        parts.append(
            "    <li>tools_used_union: "
            + ", ".join([f"<code>{escape(str(t))}</code>" for t in tools_used_union])
            + "</li>"
        )
    if tools_missing_union:
        parts.append(
            "    <li>tools_missing_union: "
            + ", ".join([f"<code>{escape(str(t))}</code>" for t in tools_missing_union])
            + "</li>"
        )
    parts.append("  </ul>")

    # Empty tool outputs (expandable)
    if isinstance(empty_tool_cases, dict) and any(v for v in empty_tool_cases.values()):
        parts.append("  <details>")
        parts.append("    <summary>Empty tool outputs (raw)</summary>")
        parts.append("    <ul>")
        for tool, cids in sorted(empty_tool_cases.items()):
            if not cids:
                continue
            items = ", ".join([f"<code>{escape(str(c))}</code>" for c in cids])
            parts.append(f"      <li><code>{escape(str(tool))}</code>: {items}</li>")
        parts.append("    </ul>")
        parts.append("  </details>")

    # Tool outputs that were fully filtered away (raw>0, filtered==0).
    if isinstance(filtered_to_zero_tool_cases, dict) and any(
        v for v in filtered_to_zero_tool_cases.values()
    ):
        parts.append("  <details>")
        parts.append("    <summary>Tool outputs filtered to zero</summary>")
        parts.append(
            "    <p class='hint'>These tools emitted findings, but 0 survived Durinn filtering (mode + exclude_prefixes/include_harness). "
            "This often means the findings were only in excluded paths like <code>benchmark/</code>.</p>"
        )
        parts.append("    <ul>")
        for tool, cids in sorted(filtered_to_zero_tool_cases.items()):
            if not cids:
                continue
            items = ", ".join([f"<code>{escape(str(c))}</code>" for c in cids])
            parts.append(f"      <li><code>{escape(str(tool))}</code>: {items}</li>")
        parts.append("    </ul>")
        parts.append("  </details>")
    parts.append("</section>")

    # Action items
    if action_items:
        parts.append("<section>")
        parts.append("  <h2>Action items</h2>")
        parts.append("  <ul>")
        for a in action_items:
            parts.append(f"    <li>{escape(str(a))}</li>")
        parts.append("  </ul>")
        parts.append("</section>")

    # Results highlights
    parts.append("<section>")
    parts.append("  <h2>Results highlights</h2>")
    if top_gap_cases:
        parts.append("  <h3>Top GT gap cases</h3>")
        parts.append("  <ul>")
        for r in top_gap_cases:
            if not isinstance(r, dict):
                continue
            cid = str(r.get("case_id") or "")
            gap_total = r.get("gap_total")
            score = r.get("gt_score_json")
            gapq = r.get("gt_gap_queue_csv")
            parts.append(
                "    <li>"
                + f"<code>{escape(cid)}</code>: gap_total=<strong>{escape(str(gap_total))}</strong> "
                + f"| gt_score: {_maybe_link(score)} "
                + f"| gt_gap_queue: {_maybe_link(gapq)}"
                + "</li>"
            )
        parts.append("  </ul>")

    if top_sev_cases:
        parts.append("  <h3>Top severity cases</h3>")
        parts.append("  <ul>")
        for r in top_sev_cases:
            if not isinstance(r, dict):
                continue
            cid = str(r.get("case_id") or "")
            sev = r.get("top_severity")
            tri = r.get("triage_rows")
            tq = r.get("triage_queue_csv")
            hp = r.get("hotspot_pack_json")
            parts.append(
                "    <li>"
                + f"<code>{escape(cid)}</code>: top_severity={_sev_badge(sev)} triage_rows=<strong>{escape(str(tri))}</strong> "
                + f"| triage_queue: {_maybe_link(tq)} "
                + f"| hotspot_pack: {_maybe_link(hp)}"
                + "</li>"
            )
        parts.append("  </ul>")
    parts.append("</section>")

    # Triage eval macro
    if macro:
        parts.append("<section>")
        parts.append("  <h2>Triage eval (macro)</h2>")
        parts.append("  <p class='hint'>Macro averages derived from <code>triage_eval_topk.csv</code> (best-effort).</p>")
        parts.append("  <div class='table-wrap'>")
        parts.append("  <table>")
        parts.append("    <thead><tr><th>strategy</th><th class='num'>k</th><th class='num'>precision</th><th class='num'>gt_coverage</th></tr></thead>")
        parts.append("    <tbody>")
        for strat, by_k in _iter_macro_rows(macro):
            for k, p, c in by_k:
                parts.append("      <tr>")
                parts.append(f"        <td><code>{escape(strat)}</code></td>")
                parts.append(f"        <td class='num'>{escape(str(k))}</td>")
                parts.append(f"        <td class='num'>{_metric_cell(p)}</td>")
                parts.append(f"        <td class='num'>{_metric_cell(c)}</td>")
                parts.append("      </tr>")
        parts.append("    </tbody>")
        parts.append("  </table>")
        parts.append("  </div>")
        parts.append("</section>")

    # Triage eval micro
    if micro:
        parts.append("<section>")
        parts.append("  <h2>Triage eval (micro)</h2>")
        parts.append("  <p class='hint'>Micro aggregation pools numerators/denominators across cases (large cases weigh more).</p>")
        parts.append("  <div class='table-wrap'>")
        parts.append("  <table>")
        parts.append("    <thead><tr><th>strategy</th><th class='num'>k</th><th class='num'>precision</th><th class='num'>gt_coverage</th></tr></thead>")
        parts.append("    <tbody>")
        for strat, by_k in _iter_macro_rows(micro):
            for k, p, c in by_k:
                parts.append("      <tr>")
                parts.append(f"        <td><code>{escape(strat)}</code></td>")
                parts.append(f"        <td class='num'>{escape(str(k))}</td>")
                parts.append(f"        <td class='num'>{_metric_cell(p)}</td>")
                parts.append(f"        <td class='num'>{_metric_cell(c)}</td>")
                parts.append("      </tr>")
        parts.append("    </tbody>")
        parts.append("  </table>")
        parts.append("  </div>")
        parts.append("</section>")

    # Lift vs baseline
    if delta_vs_baseline:
        parts.append("<section>")
        parts.append("  <h2>Lift vs baseline</h2>")
        parts.append("  <p class='hint'>Deltas are computed as (strategy - baseline) for Precision@K and GT coverage@K.</p>")
        parts.append(_render_delta_tables(delta_vs_baseline))
        parts.append("</section>")

    # Calibration support
    if owasp_support:
        parts.append("<section>")
        parts.append("  <h2>Calibration support</h2>")
        parts.append("  <ul>")
        if isinstance(min_support_by_owasp, int):
            parts.append(f"    <li>min_support_by_owasp: <code>{min_support_by_owasp}</code></li>")
        if owasp_fallback:
            parts.append(
                "    <li>owasp_fallback: "
                + ", ".join([f"<code>{escape(str(x))}</code>" for x in owasp_fallback])
                + "</li>"
            )
        parts.append("  </ul>")
        parts.append("  <div class='table-wrap'>")
        parts.append("  <table>")
        parts.append("    <thead><tr><th>OWASP</th><th class='num'>cases</th><th class='num'>clusters</th><th class='num'>gt_positive_clusters</th></tr></thead>")
        parts.append("    <tbody>")
        for owasp, v in sorted(owasp_support.items()):
            if not isinstance(v, dict):
                continue
            parts.append("      <tr>")
            parts.append(f"        <td><code>{escape(str(owasp))}</code></td>")
            parts.append(f"        <td class='num'>{escape(str(int(v.get('cases') or 0)))}</td>")
            parts.append(f"        <td class='num'>{escape(str(int(v.get('clusters') or 0)))}</td>")
            parts.append(f"        <td class='num'>{escape(str(int(v.get('gt_positive_clusters') or 0)))}</td>")
            parts.append("      </tr>")
        parts.append("    </tbody>")
        parts.append("  </table>")
        parts.append("  </div>")
        parts.append("</section>")

    # QA
    parts.append("<section>")
    parts.append("  <h2>QA</h2>")
    parts.append("  <ul>")
    if qa_scope:
        parts.append(f"    <li>scope: <code>{escape(str(qa_scope))}</code></li>")
    if qa_no_reanalyze is not None:
        parts.append(f"    <li>no_reanalyze: <code>{escape(str(qa_no_reanalyze))}</code></li>")
    if qa_result:
        status = qa_result.get("status")
        if status:
            parts.append(f"    <li>status: <code>{escape(str(status))}</code></li>")
    parts.append("  </ul>")
    parts.append("</section>")

    # Per-case drilldown
    if per_case:
        parts.append("<section>")
        parts.append("  <h2>Per-case drilldown</h2>")
        parts.append("  <div class='table-wrap'>")
        parts.append("  <table>")
        parts.append(
            "    <thead><tr>"
            "<th>case_id</th>"
            "<th class='num'>clusters</th>"
            "<th class='num'>triage_rows</th>""<th>findings raw→filtered</th>"
            "<th class='num'>gt_matched</th>"
            "<th class='num'>gt_total</th>"
            "<th class='num'>match_rate</th>"
            "<th class='num'>gap_total</th>"
            "<th>top_severity</th>"
            "<th>links</th>"
            "</tr></thead>"
        )
        parts.append("    <tbody>")
        for row in _iter_case_rows(per_case):
            parts.append("      <tr>")
            parts.append(f"        <td><code>{escape(row.get('case_id') or '')}</code></td>")
            parts.append(f"        <td class='num'>{escape(str(row.get('clusters') or 0))}</td>")
            parts.append(f"        <td class='num'>{escape(str(row.get('triage_rows') or 0))}</td>")

            # Raw vs filtered findings per tool (helps explain "not empty, but nothing survived filtering").
            raw_map = row.get("tool_findings") if isinstance(row.get("tool_findings"), dict) else {}
            fil_map = (
                row.get("tool_findings_filtered")
                if isinstance(row.get("tool_findings_filtered"), dict)
                else {}
            )
            bits: List[str] = []
            for t in sorted(raw_map.keys()):
                raw_n = raw_map.get(t)
                fil_n = fil_map.get(t)
                if raw_n is None and fil_n is None:
                    continue
                raw_s = "?" if raw_n is None else str(raw_n)
                fil_s = "?" if fil_n is None else str(fil_n)
                bits.append(
                    f"<code>{escape(str(t))}</code>: {escape(raw_s)}→{escape(fil_s)}"
                )
            findings_cell = "<br>".join(bits) if bits else "-"
            parts.append(f"        <td class='mono'>{findings_cell}</td>")
            parts.append(f"        <td class='num'>{escape(str(row.get('gt_matched') or 0))}</td>")
            parts.append(f"        <td class='num'>{escape(str(row.get('gt_total') or 0))}</td>")
            parts.append(f"        <td class='num'>{_fmt_float(row.get('match_rate'))}</td>")
            parts.append(f"        <td class='num'>{_fmt_int(row.get('gap_total'))}</td>")
            parts.append(f"        <td>{_sev_badge(row.get('top_severity'))}</td>")

            links = [
                ("manifest", row.get("analysis_manifest")),
                ("triage.csv", row.get("triage_queue_csv")),
                ("triage.json", row.get("triage_queue_json")),
                ("gt_score", row.get("gt_score_json")),
                ("gt_gap", row.get("gt_gap_queue_csv")),
                ("hotspot", row.get("hotspot_pack_json")),
            ]
            parts.append(f"        <td class='links'>{_links_inline(links)}</td>")
            parts.append("      </tr>")
        parts.append("    </tbody>")
        parts.append("  </table>")
        parts.append("  </div>")
        parts.append("</section>")

    # Where to click
    if suite_tables or self_links:
        parts.append("<section>")
        parts.append("  <h2>Where to click</h2>")
        parts.append("  <ul class='mono'>")
        for k in sorted(suite_tables.keys()):
            v = suite_tables.get(k)
            parts.append(f"    <li>{escape(str(k))}: {_maybe_link(v)}</li>")

        if isinstance(self_links, dict):
            for k in sorted(self_links.keys()):
                v = self_links.get(k)
                parts.append(f"    <li>{escape(str(k))}: {_maybe_link(v)}</li>")

        parts.append("  </ul>")
        parts.append("</section>")

    # Integrity notes
    integrity_html = _render_integrity_notes(integrity)
    if integrity_html:
        parts.append(integrity_html)

    parts.append("<footer class='footer'>")
    parts.append("  <p>Generated by <code>pipeline.analysis.suite_report</code>.</p>")
    parts.append("</footer>")

    parts.append("</main>")
    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts) + "\n"


def _iter_macro_rows(
    macro: Dict[str, Any],
) -> Iterable[Tuple[str, List[Tuple[str, Optional[float], Optional[float]]]]]:
    """Yield (strategy, rows) where rows = [(k, precision, coverage), ...]."""

    for strat, by_k in macro.items():
        if not isinstance(by_k, dict):
            continue
        rows: List[Tuple[str, Optional[float], Optional[float]]] = []
        # Sort ks numerically if possible
        for k in sorted(by_k.keys(), key=lambda x: int(x) if str(x).isdigit() else 10**9):
            vals = by_k.get(k)
            if not isinstance(vals, dict):
                continue
            p = vals.get("precision")
            c = vals.get("gt_coverage")
            rows.append((str(k), _as_float(p), _as_float(c)))
        yield str(strat), rows


def _iter_case_rows(per_case: Sequence[Any]) -> Iterable[Dict[str, Any]]:
    for r in per_case:
        if isinstance(r, dict):
            yield r


def _kpi(label: str, value: str) -> str:
    return (
        "    <div class='kpi'>"
        f"<div class='kpi-label'>{escape(label)}</div>"
        f"<div class='kpi-value'>{escape(value)}</div>"
        "</div>"
    )


def _as_float(x: Any) -> Optional[float]:
    try:
        if x is None:
            return None
        return float(x)
    except Exception:
        return None


def _fmt_float(x: Any, *, digits: int = 3) -> str:
    v = _as_float(x)
    if v is None:
        return "-"
    # avoid 'nan' bars
    if v != v:  # NaN
        return "nan"
    return f"{v:.{digits}f}"


def _fmt_int(x: Any) -> str:
    try:
        if x is None:
            return "-"
        return str(int(x))
    except Exception:
        return escape(str(x)) if x is not None else "-"


def _metric_cell(x: Optional[float]) -> str:
    if x is None:
        return "-"
    if x != x:  # NaN
        return "nan"
    pct = max(0.0, min(1.0, float(x))) * 100.0
    # Use a neutral bar; keep it readable even without CSS colors
    return (
        "<div class='metric'>"
        f"<div class='bar'><div class='bar-fill' style='width:{pct:.1f}%'></div></div>"
        f"<span class='metric-val'>{escape(f'{x:.3f}')}</span>"
        "</div>"
    )


def _render_delta_tables(delta_vs_baseline: Dict[str, Any]) -> str:
    """Render macro/micro delta-vs-baseline tables.

    The input structure is expected to match triage_eval_summary.json:

      {"macro": {strat: {k: {"precision": d, "gt_coverage": d}}},
       "micro": {...}}
    """

    out: List[str] = []

    for agg in ("macro", "micro"):
        block = delta_vs_baseline.get(agg)
        if not isinstance(block, dict) or not block:
            continue

        out.append(f"  <h3>{escape(agg)}</h3>")
        out.append("  <div class='table-wrap'>")
        out.append("  <table>")
        out.append(
            "    <thead><tr><th>strategy</th><th class='num'>k</th><th class='num'>Δ precision</th><th class='num'>Δ gt_coverage</th></tr></thead>"
        )
        out.append("    <tbody>")

        # Collect rows then sort by (strategy, k)
        rows: List[Tuple[str, str, Optional[float], Optional[float]]] = []
        for strat, by_k in block.items():
            if not isinstance(by_k, dict):
                continue
            for k in by_k.keys():
                vals = by_k.get(k)
                if not isinstance(vals, dict):
                    continue
                rows.append(
                    (
                        str(strat),
                        str(k),
                        _as_float(vals.get("precision")),
                        _as_float(vals.get("gt_coverage")),
                    )
                )

        rows.sort(key=lambda r: (r[0], int(r[1]) if r[1].isdigit() else 10**9))

        for strat, k, dp, dc in rows:
            out.append("      <tr>")
            out.append(f"        <td><code>{escape(strat)}</code></td>")
            out.append(f"        <td class='num'>{escape(str(k))}</td>")
            out.append(f"        <td class='num'>{_delta_cell(dp)}</td>")
            out.append(f"        <td class='num'>{_delta_cell(dc)}</td>")
            out.append("      </tr>")

        out.append("    </tbody>")
        out.append("  </table>")
        out.append("  </div>")

    return "\n".join(out)


def _delta_cell(x: Optional[float]) -> str:
    if x is None:
        return "-"
    if x != x:  # NaN
        return "nan"
    cls = "delta"
    if x > 0:
        cls += " delta-pos"
    elif x < 0:
        cls += " delta-neg"
    sign = "+" if x > 0 else ""
    return f"<span class='{cls}'>{escape(f'{sign}{x:.3f}')}</span>"


def _maybe_link(p: Any, *, label: Optional[str] = None) -> str:
    if not p:
        return "<span class='muted'>(missing)</span>"
    s = str(p)
    txt = label or s
    # Render as a link. With <base href='../'> this resolves relative to suite_dir.
    return f"<a href='{escape(s, quote=True)}'><code>{escape(txt)}</code></a>"


def _links_inline(items: Sequence[Tuple[str, Any]]) -> str:
    parts: List[str] = []
    for label, path in items:
        if path:
            parts.append(_maybe_link(path, label=label))
        else:
            parts.append(f"<span class='muted'>{escape(label)}: -</span>")
    return "<span class='link-row'>" + " ".join(parts) + "</span>"


def _sev_badge(sev: Any) -> str:
    s = (str(sev) if sev else "").upper().strip()
    if not s:
        return "<span class='muted'>-</span>"
    cls = {
        "CRITICAL": "sev sev-critical",
        "HIGH": "sev sev-high",
        "MEDIUM": "sev sev-medium",
        "LOW": "sev sev-low",
        "INFO": "sev sev-info",
    }.get(s, "sev")
    return f"<span class='{cls}'>{escape(s)}</span>"


def _render_integrity_notes(integrity: Dict[str, Any]) -> str:
    if not integrity:
        return ""

    notes = integrity.get("gt_ambiguity") if isinstance(integrity.get("gt_ambiguity"), dict) else {}
    if not notes:
        return ""

    evidence = integrity.get("evidence")
    warnings = integrity.get("warnings") if isinstance(integrity.get("warnings"), list) else []

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
            items.append(f"<li><code>{escape(k)}</code> = <code>{escape(str(notes.get(k)))}</code></li>")

    out: List[str] = []
    out.append("<section>")
    out.append("  <h2>Integrity notes</h2>")
    if evidence:
        out.append(f"  <p>evidence: {_maybe_link(evidence)}</p>")
    if items:
        out.append("  <ul>")
        out.extend(["    " + x for x in items])
        out.append("  </ul>")
    if warnings:
        out.append("  <details>")
        out.append("    <summary>Warnings</summary>")
        out.append("    <ul>")
        for w in warnings:
            if str(w).strip():
                out.append(f"      <li>{escape(str(w))}</li>")
        out.append("    </ul>")
        out.append("  </details>")
    out.append("</section>")
    return "\n".join(out)


_CSS = """
:root {
  --bg: #0b0f14;
  --panel: #111823;
  --panel2: #0f1620;
  --text: #e6edf3;
  --muted: #9aa7b1;
  --border: rgba(255,255,255,0.10);
  --link: #7cc4ff;
  --bar: rgba(255,255,255,0.14);
  --barfill: rgba(124,196,255,0.75);
}

@media (prefers-color-scheme: light) {
  :root {
    --bg: #ffffff;
    --panel: #f6f8fa;
    --panel2: #ffffff;
    --text: #111827;
    --muted: #4b5563;
    --border: rgba(17,24,39,0.12);
    --link: #2563eb;
    --bar: rgba(17,24,39,0.10);
    --barfill: rgba(37,99,235,0.55);
  }
}

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji";
  line-height: 1.4;
}

.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 24px;
}

.header h1 {
  margin: 0 0 8px 0;
  font-size: 28px;
}

.subhead {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  color: var(--muted);
  font-size: 13px;
}

h2 {
  margin: 28px 0 10px;
  font-size: 18px;
}

h3 {
  margin: 16px 0 8px;
  font-size: 15px;
  color: var(--muted);
}

code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  font-size: 0.95em;
}

a { color: var(--link); text-decoration: none; }
a:hover { text-decoration: underline; }

.kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

@media (max-width: 900px) {
  .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

@media (max-width: 520px) {
  .kpi-grid { grid-template-columns: 1fr; }
}

.kpi {
  border: 1px solid var(--border);
  background: linear-gradient(180deg, var(--panel), var(--panel2));
  border-radius: 10px;
  padding: 12px 12px;
}

.kpi-label {
  color: var(--muted);
  font-size: 12px;
  margin-bottom: 6px;
}

.kpi-value {
  font-size: 22px;
  font-weight: 700;
}

.hint {
  margin: 0 0 10px;
  color: var(--muted);
  font-size: 13px;
}

.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--border);
  border-radius: 10px;
}

table {
  border-collapse: collapse;
  width: 100%;
  min-width: 780px;
  background: var(--panel2);
}

thead th {
  position: sticky;
  top: 0;
  background: var(--panel);
  border-bottom: 1px solid var(--border);
  text-align: left;
  font-size: 12px;
  color: var(--muted);
  padding: 10px;
}

tbody td {
  border-bottom: 1px solid var(--border);
  padding: 10px;
  vertical-align: top;
}

td.num, th.num { text-align: right; }

.metric {
  display: flex;
  align-items: center;
  gap: 10px;
  justify-content: flex-end;
}

.bar {
  width: 120px;
  height: 10px;
  background: var(--bar);
  border-radius: 999px;
  overflow: hidden;
}

.bar-fill {
  height: 100%;
  background: var(--barfill);
}

.metric-val {
  min-width: 54px;
  text-align: right;
  font-variant-numeric: tabular-nums;
}

.muted { color: var(--muted); }

.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }

.links code { font-size: 12px; }
.link-row { display: inline-flex; gap: 8px; flex-wrap: wrap; }

.sev {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  border: 1px solid var(--border);
  font-size: 12px;
  font-weight: 600;
}

/* Severity variants keep contrast in both themes */
.sev-critical { background: rgba(239,68,68,0.18); }
.sev-high { background: rgba(245,158,11,0.18); }
.sev-medium { background: rgba(59,130,246,0.16); }
.sev-low { background: rgba(34,197,94,0.16); }
.sev-info { background: rgba(148,163,184,0.16); }

.delta {
  font-variant-numeric: tabular-nums;
  font-weight: 700;
}

.delta-pos { color: rgba(34,197,94,0.95); }
.delta-neg { color: rgba(239,68,68,0.95); }

details {
  margin-top: 10px;
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 10px;
  background: var(--panel2);
}

summary {
  cursor: pointer;
  color: var(--muted);
  font-weight: 600;
}

.footer {
  margin-top: 40px;
  color: var(--muted);
  font-size: 12px;
}
"""
