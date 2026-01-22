"""pipeline.analysis.suite.compare.load

Filesystem loaders for suite-to-suite comparison.

This module loads the small set of suite artifacts needed to compute a drift
report. It does not re-run analysis.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from pipeline.analysis.io.config_receipts import load_scanner_config
from pipeline.analysis.io.meta import read_json_if_exists
from pipeline.analysis.suite.suite_triage_calibration import tool_weights_from_calibration

from .diff import _to_float, _to_int

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

    suite_json_path: Path
    suite_json: Optional[Dict[str, Any]]

    scanner_config: Dict[str, Any]

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

    suite_json_path = suite_dir / "suite.json"
    suite_json = read_json_if_exists(suite_json_path)

    # Expected scanners: prefer manifest (explicit invocation), fallback to suite.json.
    expected_scanners: List[str] = []
    try:
        if isinstance(qa_manifest, Mapping):
            inputs = qa_manifest.get("inputs")
            if isinstance(inputs, Mapping) and isinstance(inputs.get("scanners"), list):
                expected_scanners = [str(x).strip() for x in inputs.get("scanners") if str(x).strip()]
        if not expected_scanners and isinstance(suite_json, Mapping):
            plan = suite_json.get("plan")
            if isinstance(plan, Mapping) and isinstance(plan.get("scanners"), list):
                expected_scanners = [str(x).strip() for x in plan.get("scanners") if str(x).strip()]
    except Exception:
        expected_scanners = []

    scanner_config = load_scanner_config(
        suite_dir=suite_dir,
        qa_manifest=qa_manifest,
        suite_json=suite_json,
        scanners=expected_scanners,
    )

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
        suite_json_path=suite_json_path,
        suite_json=suite_json,
        scanner_config=dict(scanner_config) if isinstance(scanner_config, dict) else {},
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
