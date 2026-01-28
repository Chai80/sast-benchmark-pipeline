"""pipeline.analysis.suite.triage_eval.io

Artifact writing for suite-level triage evaluation.

This module owns writing the CSV/JSON/MD artifacts produced by
``build_triage_eval``. Keeping it separate from the compute logic makes the
evaluation easier to reason about and easier to test.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Sequence

from pipeline.analysis.io.write_artifacts import (
    write_csv,
    write_json,
    write_text,
)

from .model import TriageEvalBuildRequest, TriageEvalPaths

from .metrics import _to_int

if TYPE_CHECKING:
    from .compute import TriageEvalComputeResult

logger = logging.getLogger(__name__)


def _stable_tool_counts_json(counts: Dict[str, int]) -> str:
    """Deterministic JSON encoding for tool-count dicts."""

    return json.dumps({k: int(v) for k, v in sorted(counts.items())}, sort_keys=True)


def _parse_tool_counts_json(raw: str, fallback_tools: Sequence[str]) -> Dict[str, int]:
    """Parse tool_counts_json, falling back to 1-per-tool from tools list."""

    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                out: Dict[str, int] = {}
                for k, v in obj.items():
                    kk = str(k).strip()
                    if not kk:
                        continue
                    out[kk] = _to_int(v, 0)
                out = {k: int(v) for k, v in out.items() if int(v) > 0}
                if out:
                    return out
        except Exception:
            pass

    return {t: 1 for t in sorted(set(str(x) for x in fallback_tools if str(x).strip()))}



def _stable_tool_counts_json(counts: Dict[str, int]) -> str:
    """Deterministic JSON encoding for tool-count dicts."""

    return json.dumps({k: int(v) for k, v in sorted(counts.items())}, sort_keys=True)


def _parse_tool_counts_json(raw: str, fallback_tools: Sequence[str]) -> Dict[str, int]:
    """Parse tool_counts_json, falling back to 1-per-tool from tools list."""

    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                out: Dict[str, int] = {}
                for k, v in obj.items():
                    kk = str(k).strip()
                    if not kk:
                        continue
                    out[kk] = _to_int(v, 0)
                out = {k: int(v) for k, v in out.items() if int(v) > 0}
                if out:
                    return out
        except Exception:
            pass

    return {t: 1 for t in sorted(set(str(x) for x in fallback_tools if str(x).strip()))}




def _append_best_effort_warning(*, out_log: Path, message: str) -> None:
    """Append a warning line to the triage-eval build log (best-effort).

    This must never raise.
    """

    try:
        out_log = Path(out_log).resolve()
        out_log.parent.mkdir(parents=True, exist_ok=True)
        with out_log.open("a", encoding="utf-8") as f:
            f.write(f"WARNING: {message}\n")
    except Exception as e:
        logger.warning("Failed to append warning to %s: %s", str(out_log), e)


def write_tables_and_summary(
    *,
    req: TriageEvalBuildRequest,
    paths: TriageEvalPaths,
    computed: "TriageEvalComputeResult",
    summary: Dict[str, Any],
    warnings: Sequence[str] = (),
) -> None:
    """Write triage-eval output artifacts.

    Notes
    -----
    - The write order and CSV fieldnames match the prior monolithic
      implementation to keep diffs stable.
    - The optional suite report is best-effort and must never fail the eval.
    """

    suite_dir = req.suite_dir_resolved
    suite_id = req.suite_id_effective
    out_dirname = req.out_dirname

    write_csv(
        paths.out_by_case_csv,
        computed.by_case_rows,
        fieldnames=[
            "suite_id",
            "case_id",
            "strategy",
            "k",
            "n_clusters",
            "has_gt",
            "gt_total",
            "precision",
            "tp_at_k",
            "denom_at_k",
            "gt_coverage",
            "gt_covered_at_k",
        ],
    )

    write_csv(
        paths.out_tool_csv,
        computed.tool_rows,
        fieldnames=[
            "suite_id",
            "tool",
            "gt_ids_covered",
            "unique_gt_ids",
            "neg_clusters",
            "exclusive_neg_clusters",
        ],
    )

    if computed.tool_marginal_rows:
        write_csv(
            paths.out_tool_marginal_csv,
            computed.tool_marginal_rows,
            fieldnames=[
                "suite_id",
                "tool",
                "strategy",
                "k",
                "precision_full",
                "precision_drop",
                "delta_precision",
                "gt_coverage_full",
                "gt_coverage_drop",
                "delta_gt_coverage",
                "neg_in_topk_full",
                "neg_in_topk_drop",
                "delta_neg_in_topk",
                "gt_ids_covered",
                "unique_gt_ids",
                "neg_clusters",
                "exclusive_neg_clusters",
                "clusters_with_tool",
                "clusters_exclusive_total",
                "clusters_exclusive_pos",
                "clusters_exclusive_neg",
            ],
        )

    write_csv(
        paths.out_topk_csv,
        computed.topk_rows,
        fieldnames=[
            "suite_id",
            "case_id",
            "strategy",
            "rank",
            "cluster_id",
            "tool_count",
            "tools_json",
            "tools",
            "max_severity",
            "max_severity_rank",
            "finding_count",
            "file_path",
            "start_line",
            "triage_rank",
            "triage_score_v1",
            "gt_overlap",
            "gt_overlap_ids_json",
            "gt_overlap_ids",
            "gt_overlap_ids_count",
            "has_gt",
            "gt_total",
            "cumulative_gt_covered",
            "cumulative_gt_coverage",
        ],
    )

    if computed.deltas_by_case_rows:
        write_csv(
            paths.out_deltas_by_case_csv,
            computed.deltas_by_case_rows,
            fieldnames=[
                "suite_id",
                "case_id",
                "strategy",
                "k",
                "n_clusters",
                "has_gt",
                "gt_total",
                "baseline_precision",
                "strategy_precision",
                "precision_delta",
                "baseline_gt_coverage",
                "strategy_gt_coverage",
                "gt_coverage_delta",
            ],
        )

    write_json(paths.out_summary_json, summary)

    _write_best_effort_log(
        out_log=paths.out_log,
        summary=summary,
        cases_without_gt=computed.cases_without_gt,
        cases_no_clusters=computed.cases_no_clusters,
        cases_with_gt_but_no_clusters=computed.cases_with_gt_but_no_clusters,
        cases_with_gt_but_no_overlaps=computed.cases_with_gt_but_no_overlaps,
        warnings=warnings,
    )

    # Best-effort: generate a human-friendly suite report alongside suite-level artifacts.
    # This is read-only (consumes existing JSON/CSV) and should never fail the eval build.
    try:
        from pipeline.analysis.suite.suite_report import write_suite_report

        # The feature package API uses out_dirname, not an out_dir Path.
        write_suite_report(
            suite_dir=suite_dir,
            suite_id=str(suite_id),
            out_dirname=str(out_dirname),
        )
    except Exception as e:
        msg = f"Failed to build suite_report (best-effort): {e}"
        logger.warning(msg)
        _append_best_effort_warning(out_log=paths.out_log, message=msg)


def _write_best_effort_log(
    *,
    out_log: Path,
    summary: Dict[str, Any],
    cases_without_gt: Sequence[str],
    cases_no_clusters: Sequence[str],
    cases_with_gt_but_no_clusters: Sequence[str],
    cases_with_gt_but_no_overlaps: Sequence[str],
    warnings: Sequence[str] = (),
) -> None:
    """Write a small build log summarizing missing/empty cases.

    This is intentionally best-effort and must never raise.
    """

    try:
        lines: List[str] = []
        lines.append(f"[{summary.get('built_at')}] triage_eval build")
        lines.append(f"suite_id        : {summary.get('suite_id')}")
        lines.append(f"dataset_csv     : {summary.get('dataset_csv')}")
        lines.append(f"cases_total     : {summary.get('cases_total')}")
        lines.append(f"cases_with_gt   : {summary.get('cases_with_gt')}")
        lines.append(f"cases_without_gt: {summary.get('cases_without_gt')}")
        if cases_without_gt:
            lines.append("")
            lines.append(f"cases_without_gt ({len(cases_without_gt)}):")
            lines.extend([f"  - {c}" for c in cases_without_gt])
        if cases_no_clusters:
            lines.append("")
            lines.append(f"cases_no_clusters ({len(cases_no_clusters)}):")
            lines.extend([f"  - {c}" for c in cases_no_clusters])
        if cases_with_gt_but_no_clusters:
            lines.append("")
            lines.append(f"cases_with_gt_but_no_clusters ({len(cases_with_gt_but_no_clusters)}):")
            lines.extend([f"  - {c}" for c in cases_with_gt_but_no_clusters])
        if cases_with_gt_but_no_overlaps:
            lines.append("")
            lines.append(f"cases_with_gt_but_no_overlaps ({len(cases_with_gt_but_no_overlaps)}):")
            lines.extend([f"  - {c}" for c in cases_with_gt_but_no_overlaps])
        if warnings:
            lines.append("")
            lines.append(f"warnings ({len(warnings)}):")
            lines.extend([f"  - {w}" for w in warnings])
        write_text(out_log, "\n".join(lines) + "\n")
    except Exception as e:
        logger.warning("Failed to write triage_eval log to %s: %s", str(out_log), e)
