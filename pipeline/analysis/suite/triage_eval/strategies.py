"""pipeline.analysis.suite.triage_eval.strategies

Ranking strategies for suite-level triage evaluation.

This module is an internal split of ``pipeline.analysis.suite.suite_triage_eval``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from pipeline.analysis.suite.suite_triage_calibration import (
    load_triage_calibration,
    tool_weights_for_owasp,
    triage_score_v1,
)

from .metrics import _to_float, _to_int, _tools_for_row


def _key_file_path(r: Dict[str, str]) -> str:
    return str(r.get("file_path") or "")


def _key_start_line(r: Dict[str, str]) -> int:
    return _to_int(r.get("start_line"), 0)


def _rank_baseline(
    rows: List[Dict[str, str]], *, use_triage_rank: bool = True
) -> List[Dict[str, str]]:
    """Baseline ranking.

    Prefer triage_rank if present *and allowed*. Otherwise, mirror triage_queue tie-breaks.

    Note
    ----
    When suite calibration exists, per-case triage_rank may already reflect a
    calibrated ordering. Callers should pass use_triage_rank=False to keep
    baseline metrics uncontaminated.
    """
    # If at least one row has a positive triage_rank, use it.
    any_rank = bool(use_triage_rank) and any(
        _to_int(r.get("triage_rank"), 0) > 0 for r in rows
    )
    if any_rank:
        return sorted(rows, key=lambda r: _to_int(r.get("triage_rank"), 10**9))

    return sorted(
        rows,
        key=lambda r: (
            -_to_int(r.get("max_severity_rank"), 0),
            -_to_int(r.get("tool_count"), 0),
            -_to_int(r.get("finding_count"), 0),
            _key_file_path(r),
            _key_start_line(r),
            str(r.get("cluster_id") or ""),
        ),
    )


def _rank_agreement(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Agreement-first ranking.

    Mirrors consensus_queue ordering: tool_count desc, then severity, then size.
    """
    return sorted(
        rows,
        key=lambda r: (
            -_to_int(r.get("tool_count"), 0),
            -_to_int(r.get("max_severity_rank"), 0),
            -_to_int(r.get("finding_count"), 0),
            _key_file_path(r),
            _key_start_line(r),
            str(r.get("cluster_id") or ""),
        ),
    )


def _load_suite_calibration(
    suite_dir: Path, *, out_dirname: str = "analysis"
) -> Optional[Dict[str, Any]]:
    """Load suite-level triage calibration if present (best-effort)."""

    p = Path(suite_dir) / out_dirname / "triage_calibration.json"
    try:
        return load_triage_calibration(p)
    except Exception:
        return None


def _rank_calibrated(
    rows: List[Dict[str, str]], *, cal: Mapping[str, Any]
) -> List[Dict[str, str]]:
    """Calibrated ranking (v1).

    Sort primarily by triage_score_v1 desc, then fall back to the legacy
    deterministic ties (mirrors triage_queue ordering).
    """

    scoring = cal.get("scoring") if isinstance(cal, dict) else None
    agreement_lambda = (
        float(scoring.get("agreement_lambda", 0.0))
        if isinstance(scoring, dict)
        else 0.0
    )
    min_support_by_owasp = (
        int(scoring.get("min_support_by_owasp", 10))
        if isinstance(scoring, dict)
        else 10
    )
    sb = scoring.get("severity_bonus") if isinstance(scoring, dict) else None
    if not isinstance(sb, dict):
        sb = {"HIGH": 0.25, "MEDIUM": 0.10, "LOW": 0.0, "UNKNOWN": 0.0}
    sev_bonus: Dict[str, float] = {str(k).upper(): float(v) for k, v in sb.items()}

    # Cache weights per OWASP id to keep scoring fast and deterministic.
    weights_cache: Dict[str, Dict[str, float]] = {}

    scored: List[Dict[str, str]] = []
    for r in rows:
        rr = dict(r)
        tools = _tools_for_row(rr)
        tool_count = _to_int(rr.get("tool_count"), default=len(tools))
        max_sev = str(rr.get("max_severity") or "UNKNOWN")

        oid = str(rr.get("owasp_id") or "").strip().upper()
        if oid not in weights_cache:
            weights_cache[oid] = tool_weights_for_owasp(
                cal, owasp_id=(oid or None), min_support=min_support_by_owasp
            )
        weights = weights_cache[oid]

        try:
            score = triage_score_v1(
                tools=tools,
                tool_count=int(tool_count),
                max_severity=max_sev,
                tool_weights=weights,
                agreement_lambda=agreement_lambda,
                severity_bonus=sev_bonus,
            )
            rr["triage_score_v1"] = str(float(f"{float(score):.6f}"))
        except Exception:
            rr["triage_score_v1"] = ""
        scored.append(rr)

    return sorted(
        scored,
        key=lambda r: (
            -_to_float(r.get("triage_score_v1"), 0.0),
            -_to_int(r.get("max_severity_rank"), 0),
            -_to_int(r.get("tool_count"), 0),
            -_to_int(r.get("finding_count"), 0),
            _key_file_path(r),
            _key_start_line(r),
            str(r.get("cluster_id") or ""),
        ),
    )


def _rank_calibrated_global(
    rows: List[Dict[str, str]], *, cal: Mapping[str, Any]
) -> List[Dict[str, str]]:
    """Calibrated ranking using *global* tool weights only.

    This matches ``triage_score_v1`` but always uses the suite-level *global*
    tool weights (no OWASP segmentation). It exists to make it easy to compare:

    - ``calibrated_global``: global-only weights
    - ``calibrated``: per-OWASP weights with deterministic fallback to global

    Behavior is otherwise identical to :func:`_rank_calibrated`.
    """

    scoring = cal.get("scoring") if isinstance(cal, dict) else None
    agreement_lambda = (
        float(scoring.get("agreement_lambda", 0.0))
        if isinstance(scoring, dict)
        else 0.0
    )
    min_support_by_owasp = (
        int(scoring.get("min_support_by_owasp", 10))
        if isinstance(scoring, dict)
        else 10
    )
    sb = scoring.get("severity_bonus") if isinstance(scoring, dict) else None
    if not isinstance(sb, dict):
        sb = {"HIGH": 0.25, "MEDIUM": 0.10, "LOW": 0.0, "UNKNOWN": 0.0}
    sev_bonus: Dict[str, float] = {str(k).upper(): float(v) for k, v in sb.items()}

    # Global weights for the whole suite.
    weights = tool_weights_for_owasp(
        cal, owasp_id=None, min_support=min_support_by_owasp
    )

    scored: List[Dict[str, str]] = []
    for r in rows:
        rr = dict(r)
        tools = _tools_for_row(rr)
        tool_count = _to_int(rr.get("tool_count"), default=len(tools))
        max_sev = str(rr.get("max_severity") or "UNKNOWN")

        try:
            score = triage_score_v1(
                tools=tools,
                tool_count=int(tool_count),
                max_severity=max_sev,
                tool_weights=weights,
                agreement_lambda=agreement_lambda,
                severity_bonus=sev_bonus,
            )
            rr["triage_score_v1"] = str(float(f"{float(score):.6f}"))
        except Exception:
            rr["triage_score_v1"] = ""
        scored.append(rr)

    return sorted(
        scored,
        key=lambda r: (
            -_to_float(r.get("triage_score_v1"), 0.0),
            -_to_int(r.get("max_severity_rank"), 0),
            -_to_int(r.get("tool_count"), 0),
            -_to_int(r.get("finding_count"), 0),
            _key_file_path(r),
            _key_start_line(r),
            str(r.get("cluster_id") or ""),
        ),
    )
