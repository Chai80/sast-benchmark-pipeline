"""pipeline.analysis.suite.triage_calibration_log

Best-effort logging helpers for triage calibration.

The calibration builder produces a JSON (and optional CSV reports). This log is
written *best-effort* to surface suspicious cases without failing the entire
run.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Mapping, Sequence

from pipeline.analysis.io.write_artifacts import write_text


def _write_best_effort_calibration_log(
    *,
    out_log: Path,
    sid: str,
    dataset_csv: Path,
    out_json: Path,
    included_cases: Sequence[str],
    excluded_cases_no_gt: Sequence[str],
    tool_stats_global: Sequence[Mapping[str, Any]],
    suspicious_cases: Sequence[Mapping[str, Any]],
    generated_at: str,
) -> None:
    """Best-effort log: surface suspicious cases explicitly."""

    try:
        lines: List[str] = []
        lines.append(f"[{generated_at}] triage_calibration build")
        lines.append(f"suite_id              : {sid}")
        lines.append(f"dataset_csv           : {dataset_csv}")
        lines.append(f"included_cases        : {len(list(included_cases))}")
        lines.append(f"excluded_cases_no_gt  : {len(list(excluded_cases_no_gt))}")
        lines.append(f"tools                 : {len(list(tool_stats_global))}")
        lines.append(f"out_json              : {out_json}")
        if suspicious_cases:
            lines.append("")
            lines.append(f"suspicious_cases ({len(list(suspicious_cases))}):")
            for sc in suspicious_cases:
                lines.append(
                    f"  - {sc.get('case_id')}: clusters={sc.get('cluster_count')} overlap_sum={sc.get('gt_overlap_sum')}"
                )
        write_text(out_log, "\n".join(lines) + "\n")
    except Exception:
        # Best-effort by design: never crash the pipeline for log output.
        pass


__all__ = [
    "_write_best_effort_calibration_log",
]
