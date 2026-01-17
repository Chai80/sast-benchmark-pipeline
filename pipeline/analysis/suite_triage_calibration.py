"""pipeline.analysis.suite_triage_calibration

Suite-level triage calibration builder.

Goal (2B)
---------
Produce a deterministic calibration artifact for triage ranking that fixes the
failure mode where single-tool clusters tie and ordering falls back to
file/line order.

Inputs
------
- runs/suites/<suite_id>/analysis/_tables/triage_dataset.csv
- runs/suites/<suite_id>/cases/<case_id>/gt/gt_score.json (GT presence gate)

Outputs
-------
- runs/suites/<suite_id>/analysis/triage_calibration.json
- (optional) runs/suites/<suite_id>/analysis/_tables/triage_calibration_report.csv
- (best-effort) runs/suites/<suite_id>/analysis/triage_calibration.log

Calibration spec (v1)
---------------------
For each tool t, compute per-cluster TP/FP on cases that have GT:

- tp_t = count of clusters where t in tools_json and gt_overlap==1
- fp_t = count of clusters where t in tools_json and gt_overlap==0

Smoothed precision:
  p_t = (tp_t + alpha) / (tp_t + fp_t + alpha + beta)

Weight (preferred):
  w_t = log(p_t / (1 - p_t)) with p clamped to [p_min, p_max]

This module also contains a small scoring helper (triage_score_v1) used by:
- per-case triage_queue ranking (when calibration file exists)
- suite_triage_eval "calibrated" strategy

Design notes
------------
- Filesystem-first and deterministic (sorted tools, stable list ordering).
- Excludes cases without GT (missing gt_score.json).
- Logs suspicious cases (has GT + has clusters + zero overlaps) so we don't
  silently learn from broken GT alignment.
"""

from __future__ import annotations

import csv
import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from pipeline.analysis.io.write_artifacts import write_csv, write_json


TRIAGE_CALIBRATION_SCHEMA_V1: str = "triage_calibration_v1"
TRIAGE_CALIBRATION_SCHEMA_VERSION: str = "triage_calibration_v2"

# Backwards compatible reader (we still accept v1 files).
TRIAGE_CALIBRATION_SUPPORTED_VERSIONS: set[str] = {
    TRIAGE_CALIBRATION_SCHEMA_V1,
    TRIAGE_CALIBRATION_SCHEMA_VERSION,
}


@dataclass(frozen=True)
class CalibrationParamsV1:
    # Smoothing
    alpha: float = 1.0
    beta: float = 1.0

    # Clamp for log-odds
    p_min: float = 0.01
    p_max: float = 0.99

    # Scoring params (stored in calibration json and used by triage_score_v1)
    agreement_lambda: float = 0.50
    severity_bonus: Mapping[str, float] = None  # type: ignore[assignment]

    # Per-OWASP selection guardrail
    #
    # A slice must have at least this many GT-scored clusters before we trust
    # its category-specific weights.
    min_support_by_owasp: int = 10

    def __post_init__(self) -> None:
        if self.severity_bonus is None:
            object.__setattr__(
                self,
                "severity_bonus",
                {
                    "HIGH": 0.25,
                    "MEDIUM": 0.10,
                    "LOW": 0.00,
                    "UNKNOWN": 0.00,
                },
            )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return int(default)
        if isinstance(x, bool):
            return int(x)
        return int(float(str(x)))
    except Exception:
        return int(default)


def _round6(x: float) -> float:
    return float(f"{float(x):.6f}")


def _parse_json_list(raw: str) -> List[str]:
    if not raw:
        return []
    try:
        v = json.loads(raw)
        if isinstance(v, list):
            return [str(x) for x in v if str(x).strip()]
    except Exception:
        return []
    return []


def _parse_tools_any(raw: Any) -> List[str]:
    """Parse tools from either tools_json (JSON list) or tools (comma string)."""
    if raw is None:
        return []

    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]

    s = str(raw).strip()
    if not s:
        return []

    # JSON list
    if s.startswith("["):
        tools = _parse_json_list(s)
        if tools:
            return tools

    # Comma-delimited
    return [t.strip() for t in s.split(",") if t.strip()]


def _clamp(p: float, lo: float, hi: float) -> float:
    return max(float(lo), min(float(hi), float(p)))


def smoothed_precision(tp: int, fp: int, *, alpha: float, beta: float) -> float:
    denom = float(tp + fp) + float(alpha) + float(beta)
    if denom <= 0:
        return 0.5
    return (float(tp) + float(alpha)) / denom


def log_odds(p: float, *, p_min: float, p_max: float) -> float:
    pp = _clamp(float(p), float(p_min), float(p_max))
    return math.log(pp / (1.0 - pp))


def tool_weights_from_calibration(cal: Mapping[str, Any]) -> Dict[str, float]:
    out: Dict[str, float] = {}
    rows = cal.get("tool_stats_global") or cal.get("tool_stats") or []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        t = str(row.get("tool") or "").strip()
        if not t:
            continue
        try:
            out[t] = float(row.get("weight"))
        except Exception:
            out[t] = 0.0
    return out


_RE_OWASP_ID = re.compile(r"^A(\d{1,2})$", re.IGNORECASE)


def _normalize_owasp_id(v: Any) -> Optional[str]:
    s = str(v or "").strip().upper()
    if not s:
        return None
    m = _RE_OWASP_ID.match(s)
    if not m:
        return None
    n = int(m.group(1))
    if n < 1 or n > 10:
        return None
    return f"A{n:02d}"


def tool_weights_for_owasp(
    cal: Mapping[str, Any],
    *,
    owasp_id: Optional[str],
    min_support: int = 10,
) -> Dict[str, float]:
    """Return tool weights for a specific OWASP category with fallback.

    Rules
    -----
    - If the calibration JSON contains a slice for `owasp_id` and that slice has
      at least `min_support` GT-scored clusters, return that slice's weights.
    - Otherwise, fall back to global weights.

    This function is intentionally small and dependency-free so both:
      - per-case triage_queue scoring, and
      - suite_triage_eval "calibrated" strategy
    can use the exact same selection logic.
    """

    global_weights = tool_weights_from_calibration(cal)
    oid = _normalize_owasp_id(owasp_id)
    if not oid:
        return global_weights

    by_owasp = cal.get("tool_stats_by_owasp") if isinstance(cal, dict) else None
    if not isinstance(by_owasp, dict):
        return global_weights

    slice_obj = by_owasp.get(oid)
    if slice_obj is None:
        return global_weights

    # v2 shape: { support: {clusters, cases, ...}, tool_stats: [...] }
    if isinstance(slice_obj, dict):
        support = slice_obj.get("support")
        clusters = 0
        if isinstance(support, dict):
            try:
                clusters = int(support.get("clusters") or 0)
            except Exception:
                clusters = 0
        tool_stats = slice_obj.get("tool_stats")
        if not isinstance(tool_stats, list):
            tool_stats = []

        if clusters < int(min_support):
            return global_weights

        out: Dict[str, float] = {}
        for row in tool_stats:
            if not isinstance(row, dict):
                continue
            t = str(row.get("tool") or "").strip()
            if not t:
                continue
            try:
                out[t] = float(row.get("weight"))
            except Exception:
                out[t] = 0.0

        return out or global_weights

    # Legacy/experimental shape: directly a list of tool_stat dicts
    if isinstance(slice_obj, list):
        # No support count available -> conservative fallback.
        return global_weights

    return global_weights


def triage_score_v1(
    *,
    tools: Sequence[str],
    tool_count: int,
    max_severity: str,
    tool_weights: Mapping[str, float],
    agreement_lambda: float,
    severity_bonus: Mapping[str, float],
) -> float:
    """Compute calibrated triage score (v1).

    triage_score_v1 = sum(tool weights) + agreement bonus + severity bonus
    """

    base = 0.0
    for t in tools or []:
        tt = str(t).strip()
        if not tt:
            continue
        base += float(tool_weights.get(tt, 0.0))

    agreement_bonus = float(agreement_lambda) * float(max(int(tool_count) - 1, 0))

    sev = str(max_severity or "").strip().upper() or "UNKNOWN"
    sev_bonus = float(severity_bonus.get(sev, severity_bonus.get("UNKNOWN", 0.0)))

    return float(base + agreement_bonus + sev_bonus)


def triage_score_v1_for_row(row: Mapping[str, Any], cal: Mapping[str, Any]) -> float:
    """Row-based scorer for triage_dataset rows."""

    scoring = cal.get("scoring", {}) if isinstance(cal, dict) else {}
    agreement_lambda = float(scoring.get("agreement_lambda", 0.0))
    severity_bonus = scoring.get("severity_bonus")
    if not isinstance(severity_bonus, dict):
        severity_bonus = {"HIGH": 0.25, "MEDIUM": 0.10, "LOW": 0.0, "UNKNOWN": 0.0}

    tools = _parse_tools_any(row.get("tools_json") or row.get("tools") or "")
    tool_count = _to_int(row.get("tool_count"), default=len(tools))

    max_sev = str(row.get("max_severity") or row.get("severity") or "UNKNOWN")

    min_support = int(scoring.get("min_support_by_owasp", 10)) if isinstance(scoring, dict) else 10
    weights = tool_weights_for_owasp(cal, owasp_id=str(row.get("owasp_id") or ""), min_support=min_support)
    return triage_score_v1(
        tools=tools,
        tool_count=tool_count,
        max_severity=max_sev,
        tool_weights=weights,
        agreement_lambda=agreement_lambda,
        severity_bonus=severity_bonus,
    )


def load_triage_calibration(path: Path) -> Optional[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return None
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return None
    sv = str(data.get("schema_version") or "")
    if sv not in TRIAGE_CALIBRATION_SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported triage calibration schema_version: {data.get('schema_version')}")
    return data


def _load_csv_rows(path: Path) -> List[Dict[str, str]]:
    with Path(path).open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [dict(r) for r in reader if isinstance(r, dict)]


def _case_has_gt(suite_dir: Path, case_id: str) -> bool:
    p = Path(suite_dir) / "cases" / str(case_id) / "gt" / "gt_score.json"
    return p.exists() and p.is_file()


def _stable_unique(items: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for x in items:
        s = str(x).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def build_triage_calibration(
    *,
    suite_dir: Path,
    suite_id: Optional[str] = None,
    params: Optional[CalibrationParamsV1] = None,
    dataset_relpath: str = "analysis/_tables/triage_dataset.csv",
    out_dirname: str = "analysis",
    write_report_csv: bool = True,
) -> Dict[str, Any]:
    """Build suite-level triage calibration JSON.

    Returns a JSON-serializable summary dict (also written to disk).
    """

    suite_dir = Path(suite_dir).resolve()
    if not suite_dir.exists() or not suite_dir.is_dir():
        raise FileNotFoundError(f"suite_dir not found: {suite_dir}")

    sid = str(suite_id) if suite_id else suite_dir.name
    params = params or CalibrationParamsV1()

    dataset_csv = suite_dir / dataset_relpath
    if not dataset_csv.exists():
        raise FileNotFoundError(f"triage_dataset.csv not found: {dataset_csv}")

    rows = _load_csv_rows(dataset_csv)

    # Determine which cases have GT artifacts.
    case_ids = sorted({str(r.get("case_id") or "").strip() for r in rows if str(r.get("case_id") or "").strip()})
    included_cases: List[str] = []
    excluded_cases_no_gt: List[str] = []
    for cid in case_ids:
        if _case_has_gt(suite_dir, cid):
            included_cases.append(cid)
        else:
            excluded_cases_no_gt.append(cid)

    included_set = set(included_cases)

    # Tool counts among included cases only.
    tp: Dict[str, int] = {}
    fp: Dict[str, int] = {}

    # Per-OWASP tool stats among included cases.
    # key: owasp_id -> per-tool tp/fp
    tp_by_owasp: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    fp_by_owasp: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    support_clusters_by_owasp: Dict[str, int] = defaultdict(int)
    support_cases_by_owasp: Dict[str, set[str]] = defaultdict(set)
    overlap_sum_by_owasp: Dict[str, int] = defaultdict(int)

    # Suspicious cases: has GT + has clusters + 0 overlaps.
    per_case_clusters: Dict[str, int] = {}
    per_case_overlap_sum: Dict[str, int] = {}

    for r in rows:
        cid = str(r.get("case_id") or "").strip()
        if not cid or cid not in included_set:
            continue

        per_case_clusters[cid] = per_case_clusters.get(cid, 0) + 1
        ov = _to_int(r.get("gt_overlap"), default=0)
        per_case_overlap_sum[cid] = per_case_overlap_sum.get(cid, 0) + ov

        tools = _parse_tools_any(r.get("tools_json") or r.get("tools") or "")
        for t in tools:
            if ov == 1:
                tp[t] = tp.get(t, 0) + 1
            else:
                fp[t] = fp.get(t, 0) + 1

        # Per-OWASP slice
        oid = _normalize_owasp_id(r.get("owasp_id"))
        if oid:
            support_clusters_by_owasp[oid] += 1
            support_cases_by_owasp[oid].add(cid)
            overlap_sum_by_owasp[oid] += int(ov)
            for t in tools:
                if ov == 1:
                    tp_by_owasp[oid][t] += 1
                else:
                    fp_by_owasp[oid][t] += 1

    suspicious_cases: List[Dict[str, Any]] = []
    for cid in included_cases:
        n = per_case_clusters.get(cid, 0)
        ov_sum = per_case_overlap_sum.get(cid, 0)
        if n > 0 and ov_sum == 0:
            suspicious_cases.append({"case_id": cid, "cluster_count": int(n), "gt_overlap_sum": int(ov_sum)})

    # Stable tool ordering.
    tools_all = sorted(set(list(tp.keys()) + list(fp.keys())))

    tool_stats_global: List[Dict[str, Any]] = []
    for t in tools_all:
        t_tp = int(tp.get(t, 0))
        t_fp = int(fp.get(t, 0))
        p = smoothed_precision(t_tp, t_fp, alpha=params.alpha, beta=params.beta)
        w = log_odds(p, p_min=params.p_min, p_max=params.p_max)

        tool_stats_global.append(
            {
                "tool": t,
                "tp": t_tp,
                "fp": t_fp,
                "p_smoothed": _round6(p),
                "weight": _round6(w),
            }
        )

    # Per-OWASP tool stats (deterministic key and list ordering).
    tool_stats_by_owasp: Dict[str, Any] = {}
    for n in range(1, 11):
        oid = f"A{n:02d}"
        if oid not in support_clusters_by_owasp:
            continue

        tp_slice = tp_by_owasp.get(oid) or {}
        fp_slice = fp_by_owasp.get(oid) or {}
        tools_slice = sorted(set(list(tp_slice.keys()) + list(fp_slice.keys())))

        stats: List[Dict[str, Any]] = []
        for t in tools_slice:
            t_tp = int(tp_slice.get(t, 0))
            t_fp = int(fp_slice.get(t, 0))
            p = smoothed_precision(t_tp, t_fp, alpha=params.alpha, beta=params.beta)
            w = log_odds(p, p_min=params.p_min, p_max=params.p_max)
            stats.append(
                {
                    "tool": t,
                    "tp": t_tp,
                    "fp": t_fp,
                    "p_smoothed": _round6(p),
                    "weight": _round6(w),
                }
            )

        tool_stats_by_owasp[oid] = {
            "support": {
                "clusters": int(support_clusters_by_owasp.get(oid, 0)),
                "cases": int(len(support_cases_by_owasp.get(oid) or set())),
                "gt_positive_clusters": int(overlap_sum_by_owasp.get(oid, 0)),
            },
            "tool_stats": stats,
        }

    out_dir = suite_dir / out_dirname
    out_json = out_dir / "triage_calibration.json"
    out_report = out_dir / "_tables" / "triage_calibration_report.csv"
    out_log = out_dir / "triage_calibration.log"

    payload: Dict[str, Any] = {
        "schema_version": TRIAGE_CALIBRATION_SCHEMA_VERSION,
        "suite_id": sid,
        "generated_at": _now_iso(),
        "input_dataset": str(dataset_csv.relative_to(suite_dir)).replace("\\", "/"),
        "alpha": float(params.alpha),
        "beta": float(params.beta),
        "p_clamp": {"min": float(params.p_min), "max": float(params.p_max)},
        "included_cases": list(included_cases),
        "excluded_cases_no_gt": list(excluded_cases_no_gt),
        "suspicious_cases": list(suspicious_cases),
        "tool_stats_global": list(tool_stats_global),
        # Backwards compatible alias for v1 consumers/tests that still read `tool_stats`.
        # Keep this during the v1->v2 transition so older tooling continues to work.
        "tool_stats": list(tool_stats_global),
        "tool_stats_by_owasp": tool_stats_by_owasp,
        "scoring": {
            "strategy": "triage_score_v1",
            "agreement_lambda": float(params.agreement_lambda),
            "severity_bonus": dict(params.severity_bonus),
            "min_support_by_owasp": int(params.min_support_by_owasp),
        },
    }

    # Deterministic JSON ordering is achieved by:
    # - stable list ordering (sorted tools/cases)
    # - dict insertion order defined above
    write_json(out_json, payload, indent=2)

    if write_report_csv:
        write_csv(
            out_report,
            tool_stats_global,
            fieldnames=["tool", "tp", "fp", "p_smoothed", "weight"],
        )

    # Best-effort log: surface suspicious cases explicitly.
    try:
        lines: List[str] = []
        lines.append(f"[{payload['generated_at']}] triage_calibration build")
        lines.append(f"suite_id              : {sid}")
        lines.append(f"dataset_csv           : {dataset_csv}")
        lines.append(f"included_cases        : {len(included_cases)}")
        lines.append(f"excluded_cases_no_gt  : {len(excluded_cases_no_gt)}")
        lines.append(f"tools                 : {len(tool_stats_global)}")
        lines.append(f"out_json              : {out_json}")
        if suspicious_cases:
            lines.append("")
            lines.append(f"suspicious_cases ({len(suspicious_cases)}):")
            for sc in suspicious_cases:
                lines.append(
                    f"  - {sc.get('case_id')}: clusters={sc.get('cluster_count')} overlap_sum={sc.get('gt_overlap_sum')}"
                )
        out_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        pass

    return {
        "suite_id": sid,
        "suite_dir": str(suite_dir),
        "dataset_csv": str(dataset_csv),
        "out_json": str(out_json),
        "out_report_csv": str(out_report) if write_report_csv else "",
        "included_cases": list(included_cases),
        "excluded_cases_no_gt": list(excluded_cases_no_gt),
        "suspicious_cases": list(suspicious_cases),
        "tools": int(len(tool_stats_global)),
        "owasp_slices": int(len(tool_stats_by_owasp)),
        "built_at": payload.get("generated_at"),
    }
