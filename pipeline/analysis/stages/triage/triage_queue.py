from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json
from pipeline.analysis.suite.suite_triage_calibration import (
    load_triage_calibration,
    tool_weights_for_owasp,
    triage_score_v1,
)
from pipeline.analysis.utils.owasp import infer_owasp

from ..common.locations import ensure_location_clusters
from ..common.severity import max_severity, severity_rank
from ..common.store_keys import StoreKeys


TRIAGE_QUEUE_SCHEMA_VERSION = "v1"

# NOTE: This list is a contract. Update tests if you change it.
TRIAGE_QUEUE_FIELDNAMES: List[str] = [
    "rank",
    "triage_score_v1",  # may be blank when no suite calibration exists
    "file_path",
    "start_line",
    "end_line",
    "tool_count",
    "tools",
    "total_findings",
    "max_severity",
    "sample_rule_id",
    "sample_title",
    "cluster_id",
]


def _as_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return float(default)


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _baseline_sort_key(r: Dict[str, Any]) -> tuple:
    """Legacy deterministic triage ordering.

    This is the stable fallback order both with and without calibration.
    """

    return (
        -_as_int(r.get("_sev_rank"), 0),
        -_as_int(r.get("tool_count"), 0),
        -_as_int(r.get("total_findings"), 0),
        str(r.get("file_path") or ""),
        _as_int(r.get("start_line"), 0),
        # Final stable tie-break key (required for determinism)
        str(r.get("cluster_id") or ""),
    )


def rank_triage_rows(rows: List[Dict[str, Any]], *, calibrated: bool) -> List[Dict[str, Any]]:
    """Sort rows deterministically and assign 1-based rank.

    Contract:
      - If calibrated: primary sort triage_score_v1 desc, then fallback to legacy deterministic order.
      - If not calibrated: legacy deterministic order unchanged.
      - Always use stable tie-break keys (file_path, start_line, cluster_id).
    """

    if calibrated:
        rows.sort(key=lambda r: (-_as_float(r.get("triage_score_v1"), 0.0),) + _baseline_sort_key(r))
    else:
        rows.sort(key=_baseline_sort_key)

    for i, r in enumerate(rows, start=1):
        r["rank"] = i
        r.pop("_sev_rank", None)
    return rows


def _choose_sample_item(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Pick a representative finding from a cluster.

    Heuristic:
      1) highest severity
      2) deterministic tiebreaks (tool, rule_id, title, finding_id)

    This keeps triage_queue.sample_* stable and more representative than "first item".
    """

    def _key(it: Dict[str, Any]) -> tuple:
        return (
            -severity_rank(it.get("severity")),
            str(it.get("tool") or ""),
            str(it.get("rule_id") or ""),
            str(it.get("title") or ""),
            str(it.get("finding_id") or ""),
        )

    best: Dict[str, Any] = {}
    best_key: tuple | None = None
    for it in items or []:
        if not isinstance(it, dict):
            continue
        k = _key(it)
        if best_key is None or k < best_key:
            best_key = k
            best = it
    return best


@register_stage(
    "triage_queue",
    kind="analysis",
    description="Create a ranked triage queue of hotspots to review first.",
)
def stage_triage(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    # Optional suite-level calibration (best-effort).
    #
    # Expected suite layout:
    #   runs/suites/<suite_id>/cases/<case_id>/analysis/  (ctx.out_dir)
    #   runs/suites/<suite_id>/analysis/triage_calibration.json
    cal: Dict[str, Any] | None = None
    cal_weights: Dict[str, float] = {}
    agreement_lambda: float = 0.0
    severity_bonus: Dict[str, float] = {"HIGH": 0.25, "MEDIUM": 0.10, "LOW": 0.0, "UNKNOWN": 0.0}
    min_support_by_owasp: int = 10

    # Best-effort category label for selecting per-OWASP calibration weights.
    case_owasp_id: str | None = None
    try:
        oid, _title = infer_owasp(ctx.case_id, out_dir=Path(ctx.out_dir))
        case_owasp_id = oid
    except Exception:
        case_owasp_id = None

    if ctx.suite_id:
        try:
            out_dir = Path(ctx.out_dir)
            suite_dir = out_dir.parent.parent.parent if out_dir.name == "analysis" else None
            if suite_dir and suite_dir.name == str(ctx.suite_id):
                cal_path = suite_dir / "analysis" / "triage_calibration.json"
                cal = load_triage_calibration(cal_path)
                if cal:
                    scoring = cal.get("scoring") if isinstance(cal, dict) else None
                    if isinstance(scoring, dict):
                        agreement_lambda = float(scoring.get("agreement_lambda", 0.0))
                        try:
                            min_support_by_owasp = int(scoring.get("min_support_by_owasp", 10))
                        except Exception:
                            min_support_by_owasp = 10
                        sb = scoring.get("severity_bonus")
                        if isinstance(sb, dict):
                            severity_bonus = {str(k).upper(): float(v) for k, v in sb.items()}

                    # Select per-OWASP weights when sufficiently supported; otherwise fall back to global.
                    cal_weights = tool_weights_for_owasp(cal, owasp_id=case_owasp_id, min_support=min_support_by_owasp)
        except Exception:
            # Never fail per-case triage queue due to calibration issues.
            cal = None
            cal_weights = {}

    clusters = ensure_location_clusters(ctx, store)

    rows: List[Dict[str, Any]] = []
    for c in clusters:
        if not isinstance(c, dict):
            continue

        items = list(c.get("items") or [])
        tool_counts = Counter()
        for it in items:
            if not isinstance(it, dict):
                continue
            tool_counts[str(it.get("tool") or "")] += 1

        sev, sev_rank = max_severity(items)
        sample = _choose_sample_item(items)
        title = str(sample.get("title") or "")
        rule_id = str(sample.get("rule_id") or "")

        # Calibrated score (v1) when suite calibration exists.
        # If missing, score is blank and the stage uses the baseline ordering.
        score_v1: str | float = ""
        if cal:
            try:
                score = triage_score_v1(
                    tools=list(c.get("tools") or []),
                    tool_count=int(c.get("tool_count") or 0),
                    max_severity=str(sev or "UNKNOWN"),
                    tool_weights=cal_weights,
                    agreement_lambda=agreement_lambda,
                    severity_bonus=severity_bonus,
                )
                score_v1 = float(f"{float(score):.6f}")
            except Exception:
                score_v1 = ""

        rows.append(
            {
                "file_path": c.get("file_path"),
                "start_line": c.get("start_line"),
                "end_line": c.get("end_line"),
                "tools": ",".join(c.get("tools") or []),
                "tool_count": int(c.get("tool_count") or 0),
                "total_findings": int(sum(tool_counts.values())),
                "max_severity": sev,
                "triage_score_v1": score_v1,
                "sample_rule_id": rule_id,
                "sample_title": title,
                "cluster_id": c.get("cluster_id"),
                "_sev_rank": sev_rank,
            }
        )

    # Ranking
    # -------
    # If calibration exists, rank primarily by triage_score_v1 (desc), then fall
    # back to the legacy deterministic order.
    #
    # If calibration does not exist, keep the baseline ordering unchanged.
    rank_triage_rows(rows, calibrated=bool(cal))

    store.put(StoreKeys.TRIAGE_ROWS, rows)

    out_csv = Path(ctx.out_dir) / "triage_queue.csv"
    out_json = Path(ctx.out_dir) / "triage_queue.json"
    if "csv" in ctx.formats:
        write_csv(
            out_csv,
            rows,
            fieldnames=TRIAGE_QUEUE_FIELDNAMES,
        )
        store.add_artifact("triage_queue_csv", out_csv)
    if "json" in ctx.formats:
        write_json(out_json, rows)
        store.add_artifact("triage_queue_json", out_json)

    return {"rows": len(rows), "top_tool_count": int(rows[0]["tool_count"]) if rows else 0, "top_severity": (rows[0]["max_severity"] if rows else "")}

