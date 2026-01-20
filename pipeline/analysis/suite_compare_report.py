"""pipeline.analysis.suite_compare_report

Suite-to-suite drift comparison.

Purpose
-------
This module compares two existing suite runs under ``runs/suites/<suite_id>/``
and writes a small, deterministic report under ``analysis/_tables``.

The report is meant to answer, in one place:

- Did policy/config change? (especially GT tolerance policy)
- Did suite-level triage metrics change? (precision@K, GT coverage@K)
- Did calibration weights drift? (global + optional per-OWASP slices)
- Did tool contribution/noise attribution change?

Outputs
-------
Written under ``runs/suites/<suite_out>/analysis/_tables``:

- suite_compare_report.json
- suite_compare_report.csv

Design notes
------------
- Filesystem-first: compare existing artifacts; do not re-run analysis.
- Deterministic: stable ordering, no prompts.
- Best-effort: missing optional inputs are recorded as warnings.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from pipeline.analysis.io.meta import read_json_if_exists
from pipeline.analysis.io.write_artifacts import write_csv, write_json
from pipeline.analysis.suite_triage_calibration import tool_weights_from_calibration


SUITE_COMPARE_REPORT_SCHEMA_V1 = "suite_compare_report_v1"


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _to_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return int(default)
        if isinstance(x, bool):
            return int(x)
        return int(float(str(x)))
    except Exception:
        return int(default)


def _to_float(x: Any, default: Optional[float] = None) -> Optional[float]:
    try:
        if x is None:
            return default
        s = str(x).strip()
        if s == "":
            return default
        return float(s)
    except Exception:
        return default


def _delta(a: Any, b: Any) -> Optional[float]:
    aa = _to_float(a, None)
    bb = _to_float(b, None)
    if aa is None or bb is None:
        return None
    return float(bb) - float(aa)


def _load_csv_rows(path: Path) -> List[Dict[str, str]]:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return []
    with p.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        out: List[Dict[str, str]] = []
        for r in reader:
            if isinstance(r, dict):
                out.append({str(k): str(v) for k, v in r.items() if k is not None})
        return out


def _parse_json_list(raw: str) -> List[str]:
    if not raw:
        return []
    s = str(raw).strip()
    if not s:
        return []
    if not s.startswith("["):
        return []
    try:
        v = json.loads(s)
    except Exception:
        return []
    if not isinstance(v, list):
        return []
    return [str(x).strip() for x in v if str(x).strip()]


def _parse_tools_any(tools_json: str, tools_csv: str) -> List[str]:
    tools = _parse_json_list(tools_json)
    if tools:
        return sorted(set(tools))
    parts = [p.strip() for p in str(tools_csv or "").split(",")]
    return sorted(set([p for p in parts if p]))


@dataclass(frozen=True)
class SuiteArtifacts:
    suite_id: str
    suite_dir: Path

    qa_manifest_path: Optional[Path]
    qa_manifest: Optional[Dict[str, Any]]

    eval_summary_path: Optional[Path]
    eval_summary: Optional[Dict[str, Any]]

    dataset_csv: Optional[Path]
    tool_utility_csv: Optional[Path]
    calibration_json: Optional[Path]
    tool_marginal_csv: Optional[Path]


def _find_first_existing(paths: Sequence[Path]) -> Optional[Path]:
    for p in paths:
        if Path(p).exists():
            return Path(p)
    return None


def _load_suite_artifacts(suite_dir: Path) -> Tuple[SuiteArtifacts, List[str]]:
    """Load suite artifacts needed for comparison.

    Returns (artifacts, warnings).
    """

    suite_dir = Path(suite_dir).resolve()
    sid = suite_dir.name

    analysis_dir = suite_dir / "analysis"
    tables_dir = analysis_dir / "_tables"

    qa_manifest_path = _find_first_existing(
        [analysis_dir / "qa_manifest.json", analysis_dir / "qa_calibration_manifest.json"]
    )
    qa_manifest = read_json_if_exists(qa_manifest_path) if qa_manifest_path else None

    eval_summary_path = tables_dir / "triage_eval_summary.json"
    eval_summary = read_json_if_exists(eval_summary_path)

    dataset_csv = tables_dir / "triage_dataset.csv"
    tool_utility_csv = tables_dir / "triage_tool_utility.csv"
    calibration_json = analysis_dir / "triage_calibration.json"
    tool_marginal_csv = tables_dir / "triage_tool_marginal.csv"

    warnings: List[str] = []
    if qa_manifest_path is None:
        warnings.append("qa_manifest missing")
    if eval_summary is None:
        warnings.append("triage_eval_summary.json missing")

    if not dataset_csv.exists():
        dataset_csv = None
        warnings.append("triage_dataset.csv missing")

    if not tool_utility_csv.exists():
        tool_utility_csv = None
        warnings.append("triage_tool_utility.csv missing")

    if not calibration_json.exists():
        calibration_json = None
        warnings.append("triage_calibration.json missing")

    if not tool_marginal_csv.exists():
        tool_marginal_csv = None

    arts = SuiteArtifacts(
        suite_id=str(sid),
        suite_dir=suite_dir,
        qa_manifest_path=qa_manifest_path,
        qa_manifest=qa_manifest,
        eval_summary_path=eval_summary_path if eval_summary else None,
        eval_summary=eval_summary,
        dataset_csv=dataset_csv,
        tool_utility_csv=tool_utility_csv,
        calibration_json=calibration_json,
        tool_marginal_csv=tool_marginal_csv,
    )
    return arts, warnings


def _extract_gt_policy(manifest: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not isinstance(manifest, Mapping):
        return {}
    inputs = manifest.get("inputs")
    if not isinstance(inputs, Mapping):
        return {}
    pol = inputs.get("gt_tolerance_policy")
    if not isinstance(pol, Mapping):
        return {}
    return dict(pol)


def _extract_eval(ev: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not isinstance(ev, Mapping):
        return {}
    out: Dict[str, Any] = {}
    for agg in ("micro", "macro"):
        obj = ev.get(agg)
        if isinstance(obj, Mapping):
            out[agg] = dict(obj)
    return out


def _dataset_counts(dataset_csv: Optional[Path]) -> Dict[str, Any]:
    if dataset_csv is None:
        return {}
    rows = _load_csv_rows(dataset_csv)
    total = len(rows)
    pos = 0
    neg = 0
    case_ids: set[str] = set()
    tool_cluster_counts: Dict[str, int] = {}

    for r in rows:
        case_ids.add(str(r.get("case_id") or ""))
        if _to_int(r.get("gt_overlap"), 0) == 1:
            pos += 1
        else:
            neg += 1

        tools = _parse_tools_any(str(r.get("tools_json") or ""), str(r.get("tools") or ""))
        for t in tools:
            tool_cluster_counts[t] = int(tool_cluster_counts.get(t, 0)) + 1

    tools_sorted = sorted(tool_cluster_counts.keys())
    return {
        "clusters_total": int(total),
        "clusters_gt_pos": int(pos),
        "clusters_gt_neg": int(neg),
        "cases_seen": int(len([c for c in case_ids if c])),
        "clusters_by_tool": {t: int(tool_cluster_counts[t]) for t in tools_sorted},
    }


def _load_calibration_weights(cal_path: Optional[Path]) -> Tuple[Dict[str, float], Dict[str, Dict[str, float]]]:
    """Return (global_weights, weights_by_owasp).

    weights_by_owasp is best-effort from triage_calibration.json v2 shape.
    """

    if cal_path is None:
        return {}, {}
    cal = read_json_if_exists(cal_path)
    if not isinstance(cal, Mapping):
        return {}, {}

    global_w = tool_weights_from_calibration(cal)

    by_owasp: Dict[str, Dict[str, float]] = {}
    raw_by = cal.get("tool_stats_by_owasp")
    if isinstance(raw_by, Mapping):
        for oid, slice_obj in raw_by.items():
            if not isinstance(slice_obj, Mapping):
                continue
            tool_stats = slice_obj.get("tool_stats")
            if not isinstance(tool_stats, list):
                continue
            w: Dict[str, float] = {}
            for row in tool_stats:
                if not isinstance(row, Mapping):
                    continue
                t = str(row.get("tool") or "").strip()
                if not t:
                    continue
                try:
                    w[t] = float(row.get("weight"))
                except Exception:
                    w[t] = 0.0
            if w:
                by_owasp[str(oid)] = w

    return global_w, by_owasp


def _load_tool_utility(tool_utility_csv: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    if tool_utility_csv is None:
        return {}
    rows = _load_csv_rows(tool_utility_csv)
    out: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        tool = str(r.get("tool") or "").strip()
        if not tool:
            continue
        out[tool] = {
            "gt_ids_covered": _to_int(r.get("gt_ids_covered"), 0),
            "unique_gt_ids": _to_int(r.get("unique_gt_ids"), 0),
            "neg_clusters": _to_int(r.get("neg_clusters"), 0),
            "exclusive_neg_clusters": _to_int(r.get("exclusive_neg_clusters"), 0),
        }
    return out


def _load_tool_marginal(tool_marginal_csv: Optional[Path]) -> Dict[Tuple[str, str, int], Dict[str, Any]]:
    """Best-effort loader for triage_tool_marginal.csv (PR6).

    Returns dict keyed by (tool, strategy, k) with selected delta metrics.
    """

    if tool_marginal_csv is None:
        return {}

    rows = _load_csv_rows(tool_marginal_csv)
    out: Dict[Tuple[str, str, int], Dict[str, Any]] = {}

    for r in rows:
        tool = str(r.get("tool") or "").strip()
        strat = str(r.get("strategy") or "").strip()
        k = _to_int(r.get("k"), 0)
        if not tool or not strat or k <= 0:
            continue

        # Column names are best-effort; tolerate partial tables.
        row_out: Dict[str, Any] = {}
        for key in (
            "delta_precision",
            "delta_gt_coverage",
            "delta_neg_in_topk",
        ):
            if key in r:
                row_out[key] = _to_float(r.get(key), None)

        if row_out:
            out[(tool, strat, int(k))] = row_out

    return out


def build_suite_compare_report(
    *,
    suite_dir_a: str | Path,
    suite_dir_b: str | Path,
    out_suite_dir: Optional[str | Path] = None,
    out_basename: str = "suite_compare_report",
    include_tool_marginal: bool = True,
) -> Dict[str, Any]:
    """Compare two suite dirs and write a report.

    Parameters
    ----------
    suite_dir_a, suite_dir_b:
        Existing suite directories, e.g. runs/suites/20260101T...Z.

    out_suite_dir:
        Where to write the report. Defaults to suite_dir_a.

    out_basename:
        Basename for output files under analysis/_tables.

    include_tool_marginal:
        If True, include triage_tool_marginal.csv comparisons when both suites
        have the file.
    """

    a_dir = Path(suite_dir_a).resolve()
    b_dir = Path(suite_dir_b).resolve()

    out_dir = Path(out_suite_dir).resolve() if out_suite_dir else a_dir
    out_tables = out_dir / "analysis" / "_tables"

    a, warn_a = _load_suite_artifacts(a_dir)
    b, warn_b = _load_suite_artifacts(b_dir)

    # Require eval summaries for meaningful drift comparison.
    if a.eval_summary is None or b.eval_summary is None:
        missing: List[str] = []
        if a.eval_summary is None:
            missing.append(f"{a.suite_id}: triage_eval_summary.json")
        if b.eval_summary is None:
            missing.append(f"{b.suite_id}: triage_eval_summary.json")
        raise SystemExit("Cannot compare suites; missing required eval summary: " + ", ".join(missing))

    # Extract key inputs.
    pol_a = _extract_gt_policy(a.qa_manifest)
    pol_b = _extract_gt_policy(b.qa_manifest)

    eval_a = _extract_eval(a.eval_summary)
    eval_b = _extract_eval(b.eval_summary)

    ds_a = _dataset_counts(a.dataset_csv)
    ds_b = _dataset_counts(b.dataset_csv)

    cal_w_a, cal_by_owasp_a = _load_calibration_weights(a.calibration_json)
    cal_w_b, cal_by_owasp_b = _load_calibration_weights(b.calibration_json)

    util_a = _load_tool_utility(a.tool_utility_csv)
    util_b = _load_tool_utility(b.tool_utility_csv)

    marg_a = _load_tool_marginal(a.tool_marginal_csv) if include_tool_marginal else {}
    marg_b = _load_tool_marginal(b.tool_marginal_csv) if include_tool_marginal else {}

    rows_csv: List[Dict[str, Any]] = []

    def add_row(
        *,
        section: str,
        name: str,
        a_val: Any,
        b_val: Any,
        delta_val: Any = None,
        tool: str = "",
        strategy: str = "",
        k: Any = "",
        notes: str = "",
    ) -> None:
        rows_csv.append(
            {
                "section": str(section),
                "name": str(name),
                "tool": str(tool or ""),
                "strategy": str(strategy or ""),
                "k": "" if k in (None, "") else int(k),
                "a": "" if a_val is None else a_val,
                "b": "" if b_val is None else b_val,
                "delta": "" if delta_val is None else delta_val,
                "notes": str(notes or ""),
            }
        )

    # --- Policy diff -------------------------------------------------
    def _pol_get(pol: Mapping[str, Any], path: Sequence[str]) -> Any:
        cur: Any = pol
        for key in path:
            if not isinstance(cur, Mapping):
                return None
            cur = cur.get(key)
        return cur

    # Flat policy keys (keep CSV small)
    pol_fields: List[Tuple[str, Sequence[str]]] = [
        ("initial_gt_tolerance", ("initial_gt_tolerance",)),
        ("effective_gt_tolerance", ("effective_gt_tolerance",)),
        ("sweep.enabled", ("sweep", "enabled")),
        ("sweep.candidates", ("sweep", "candidates")),
        ("auto.enabled", ("auto", "enabled")),
        ("auto.min_fraction", ("auto", "min_fraction")),
    ]

    for name, path in pol_fields:
        va = _pol_get(pol_a, path)
        vb = _pol_get(pol_b, path)
        d = _delta(va, vb) if isinstance(va, (int, float, str)) and isinstance(vb, (int, float, str)) else None
        add_row(section="policy", name=name, a_val=va, b_val=vb, delta_val=d)

    # Selection warnings are lists; represent as JSON strings.
    sel_warn_a = _pol_get(pol_a, ("auto", "warnings"))
    sel_warn_b = _pol_get(pol_b, ("auto", "warnings"))
    add_row(
        section="policy",
        name="auto.warnings",
        a_val=json.dumps(sel_warn_a or []),
        b_val=json.dumps(sel_warn_b or []),
        delta_val=None,
    )

    # --- Dataset counts ---------------------------------------------
    for key in ("clusters_total", "clusters_gt_pos", "clusters_gt_neg", "cases_seen"):
        va = ds_a.get(key)
        vb = ds_b.get(key)
        add_row(section="dataset", name=key, a_val=va, b_val=vb, delta_val=_delta(va, vb))

    # --- Eval diff (micro/macro) ------------------------------------
    def _strategy_order(name: str) -> Tuple[int, str]:
        order = {"baseline": 0, "agreement": 1, "calibrated": 2}
        return (order.get(name, 99), str(name))

    for agg in ("micro", "macro"):
        obj_a = eval_a.get(agg) if isinstance(eval_a, dict) else {}
        obj_b = eval_b.get(agg) if isinstance(eval_b, dict) else {}

        strat_keys = sorted(set(list(obj_a.keys()) + list(obj_b.keys())), key=_strategy_order)

        for strat in strat_keys:
            ka_obj = obj_a.get(strat) if isinstance(obj_a, dict) else {}
            kb_obj = obj_b.get(strat) if isinstance(obj_b, dict) else {}

            ks = set()
            if isinstance(ka_obj, Mapping):
                ks.update([str(k) for k in ka_obj.keys()])
            if isinstance(kb_obj, Mapping):
                ks.update([str(k) for k in kb_obj.keys()])

            # Sort K numerically when possible.
            def _k_key(s: str) -> Tuple[int, str]:
                try:
                    return (int(s), s)
                except Exception:
                    return (10**9, s)

            for k_str in sorted(ks, key=_k_key):
                ra = ka_obj.get(k_str) if isinstance(ka_obj, Mapping) else None
                rb = kb_obj.get(k_str) if isinstance(kb_obj, Mapping) else None

                pa = ra.get("precision") if isinstance(ra, Mapping) else None
                pb = rb.get("precision") if isinstance(rb, Mapping) else None
                ca = ra.get("gt_coverage") if isinstance(ra, Mapping) else None
                cb = rb.get("gt_coverage") if isinstance(rb, Mapping) else None

                add_row(
                    section=f"eval_{agg}",
                    name="precision",
                    strategy=strat,
                    k=_to_int(k_str, 0),
                    a_val=pa,
                    b_val=pb,
                    delta_val=_delta(pa, pb),
                )
                add_row(
                    section=f"eval_{agg}",
                    name="gt_coverage",
                    strategy=strat,
                    k=_to_int(k_str, 0),
                    a_val=ca,
                    b_val=cb,
                    delta_val=_delta(ca, cb),
                )

    # --- Calibration drift (global weights) -------------------------
    tools = sorted(set(list(cal_w_a.keys()) + list(cal_w_b.keys())))
    for t in tools:
        wa = cal_w_a.get(t)
        wb = cal_w_b.get(t)
        add_row(
            section="calibration_weight_global",
            name="weight",
            tool=t,
            a_val=wa,
            b_val=wb,
            delta_val=_delta(wa, wb),
        )

    # --- Calibration drift (per-OWASP weights; best-effort) ----------
    owasp_ids = sorted(set(list(cal_by_owasp_a.keys()) + list(cal_by_owasp_b.keys())))
    for oid in owasp_ids:
        wa_map = cal_by_owasp_a.get(oid, {})
        wb_map = cal_by_owasp_b.get(oid, {})
        tools2 = sorted(set(list(wa_map.keys()) + list(wb_map.keys())))
        for t in tools2:
            add_row(
                section="calibration_weight_by_owasp",
                name=f"weight:{oid}",
                tool=t,
                a_val=wa_map.get(t),
                b_val=wb_map.get(t),
                delta_val=_delta(wa_map.get(t), wb_map.get(t)),
            )

    # --- Tool utility drift -----------------------------------------
    util_tools = sorted(set(list(util_a.keys()) + list(util_b.keys())))
    for t in util_tools:
        ra = util_a.get(t, {})
        rb = util_b.get(t, {})
        for field in ("gt_ids_covered", "unique_gt_ids", "neg_clusters", "exclusive_neg_clusters"):
            va = ra.get(field)
            vb = rb.get(field)
            add_row(
                section="tool_utility",
                name=field,
                tool=t,
                a_val=va,
                b_val=vb,
                delta_val=_delta(va, vb),
            )

    # --- Tool marginal drift (PR6; optional) -------------------------
    if include_tool_marginal and marg_a and marg_b:
        keys = sorted(set(list(marg_a.keys()) + list(marg_b.keys())))
        for (tool, strat, k) in keys:
            ra = marg_a.get((tool, strat, k), {})
            rb = marg_b.get((tool, strat, k), {})
            for field in ("delta_precision", "delta_gt_coverage", "delta_neg_in_topk"):
                va = ra.get(field)
                vb = rb.get(field)
                add_row(
                    section="tool_marginal",
                    name=field,
                    tool=tool,
                    strategy=strat,
                    k=int(k),
                    a_val=va,
                    b_val=vb,
                    delta_val=_delta(va, vb),
                )

    # --- Alerts ------------------------------------------------------
    alerts: List[str] = []
    try:
        eff_a = _pol_get(pol_a, ("effective_gt_tolerance",))
        eff_b = _pol_get(pol_b, ("effective_gt_tolerance",))
        if _to_int(eff_a, 0) != _to_int(eff_b, 0):
            alerts.append(f"GT tolerance changed: {eff_a} -> {eff_b}")
    except Exception:
        pass

    if warn_a:
        alerts.append(f"Suite A warnings: {', '.join(sorted(set(warn_a)))}")
    if warn_b:
        alerts.append(f"Suite B warnings: {', '.join(sorted(set(warn_b)))}")

    # Emit alerts into CSV too.
    for msg in alerts:
        add_row(section="alerts", name="alert", a_val="", b_val="", delta_val=None, notes=str(msg))

    # Stable sort for CSV.
    section_order = {
        "policy": 0,
        "dataset": 1,
        "eval_micro": 2,
        "eval_macro": 3,
        "calibration_weight_global": 4,
        "calibration_weight_by_owasp": 5,
        "tool_utility": 6,
        "tool_marginal": 7,
        "alerts": 99,
    }

    def _row_key(r: Mapping[str, Any]) -> Tuple[int, str, str, str, int]:
        sec = str(r.get("section") or "")
        name = str(r.get("name") or "")
        tool = str(r.get("tool") or "")
        strat = str(r.get("strategy") or "")
        k = _to_int(r.get("k"), 0)
        return (section_order.get(sec, 50), sec, name + ":" + tool + ":" + strat, str(tool) + str(strat), int(k))

    rows_csv.sort(key=_row_key)

    out_json = out_tables / f"{out_basename}.json"
    out_csv = out_tables / f"{out_basename}.csv"

    report: Dict[str, Any] = {
        "schema_version": SUITE_COMPARE_REPORT_SCHEMA_V1,
        "generated_at": _now_iso_utc(),
        "suite_a": {
            "suite_id": a.suite_id,
            "suite_dir": str(a.suite_dir),
            "qa_manifest_path": "" if a.qa_manifest_path is None else str(a.qa_manifest_path),
            "eval_summary_path": "" if a.eval_summary_path is None else str(a.eval_summary_path),
            "dataset_csv": "" if a.dataset_csv is None else str(a.dataset_csv),
            "tool_utility_csv": "" if a.tool_utility_csv is None else str(a.tool_utility_csv),
            "calibration_json": "" if a.calibration_json is None else str(a.calibration_json),
            "tool_marginal_csv": "" if a.tool_marginal_csv is None else str(a.tool_marginal_csv),
        },
        "suite_b": {
            "suite_id": b.suite_id,
            "suite_dir": str(b.suite_dir),
            "qa_manifest_path": "" if b.qa_manifest_path is None else str(b.qa_manifest_path),
            "eval_summary_path": "" if b.eval_summary_path is None else str(b.eval_summary_path),
            "dataset_csv": "" if b.dataset_csv is None else str(b.dataset_csv),
            "tool_utility_csv": "" if b.tool_utility_csv is None else str(b.tool_utility_csv),
            "calibration_json": "" if b.calibration_json is None else str(b.calibration_json),
            "tool_marginal_csv": "" if b.tool_marginal_csv is None else str(b.tool_marginal_csv),
        },
        "warnings": {
            "suite_a": list(sorted(set(warn_a))),
            "suite_b": list(sorted(set(warn_b))),
        },
        "alerts": list(alerts),
        "diff": {
            "gt_tolerance_policy": {
                "a": pol_a,
                "b": pol_b,
            },
            "dataset_counts": {
                "a": ds_a,
                "b": ds_b,
            },
            "calibration_weights_global": {
                "a": cal_w_a,
                "b": cal_w_b,
            },
            "tool_utility": {
                "a": util_a,
                "b": util_b,
            },
        },
        "out_csv": str(out_csv),
        "out_json": str(out_json),
    }

    # Write outputs.
    write_json(out_json, report)
    write_csv(
        out_csv,
        rows_csv,
        fieldnames=["section", "name", "tool", "strategy", "k", "a", "b", "delta", "notes"],
    )

    return {
        "suite_a": a.suite_id,
        "suite_b": b.suite_id,
        "out_csv": str(out_csv),
        "out_json": str(out_json),
        "alerts": list(alerts),
    }
