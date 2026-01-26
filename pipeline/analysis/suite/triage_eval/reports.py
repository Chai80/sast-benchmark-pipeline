"""pipeline.analysis.suite.triage_eval.reports

Suite-level triage evaluation builder.

This module intentionally keeps the public entrypoint
``build_triage_eval()`` small and readable by delegating:

- input loading to :mod:`pipeline.analysis.suite.triage_eval.load`
- metric computation to :mod:`pipeline.analysis.suite.triage_eval.compute`
- artifact writing to :mod:`pipeline.analysis.suite.triage_eval.io`

The goal is to prevent ``build_triage_eval`` from becoming a monolith and to
make the compute logic testable without filesystem I/O.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .compute import compute_triage_eval
from .io import write_readme, write_tables_and_summary
from .load import load_strategies, load_triage_dataset, normalize_ks, resolve_case_ids
from .model import TriageEvalBuildRequest, TriageEvalPaths


logger = logging.getLogger(__name__)

def _now_iso() -> str:
    # Keep the raw ISO timestamp (including microseconds) for backwards
    # compatibility with existing artifacts.
    return datetime.now(timezone.utc).isoformat()


def build_triage_eval(
    *,
    suite_dir: Path,
    suite_id: Optional[str] = None,
    ks: Sequence[int] = (1, 3, 5, 10, 25, 50),
    out_dirname: str = "analysis",
    include_tool_marginal: bool = True,
    dataset_relpath: str = "analysis/_tables/triage_dataset.csv",
) -> Dict[str, Any]:
    """Compute suite-level triage evaluation metrics.

    Returns a JSON-serializable summary dict.
    """

    req = TriageEvalBuildRequest(
        suite_dir=Path(suite_dir),
        suite_id=suite_id,
        ks=ks,
        out_dirname=out_dirname,
        include_tool_marginal=bool(include_tool_marginal),
        dataset_relpath=str(dataset_relpath),
    )

    suite_dir = req.suite_dir_resolved
    if not suite_dir.exists() or not suite_dir.is_dir():
        raise FileNotFoundError(f"suite_dir not found: {suite_dir}")

    sid = req.suite_id_effective

    # --- Load inputs -------------------------------------------------
    dataset_csv, _rows, by_case = load_triage_dataset(suite_dir=suite_dir, dataset_relpath=req.dataset_relpath)
    cases_dir, case_ids = resolve_case_ids(suite_dir=suite_dir, by_case=by_case)
    cal, strategies = load_strategies(suite_dir=suite_dir, out_dirname=req.out_dirname)

    k_list = normalize_ks(req.ks)
    max_k = max(k_list) if k_list else 0

    # --- Resolve output paths ---------------------------------------
    paths = TriageEvalPaths.for_suite(suite_dir=suite_dir, out_dirname=req.out_dirname)
    paths.out_tables.mkdir(parents=True, exist_ok=True)

    # Small, human-friendly overview next to the tables (best-effort).
    readme_path: Optional[Path] = None
    warnings: List[str] = []
    try:
        readme_path = write_readme(out_tables=paths.out_tables, suite_id=sid, ks=k_list)
    except Exception as e:
        msg = f"Failed to write triage_eval README (best-effort): {e}"
        warnings.append(msg)
        logger.warning(msg)
        readme_path = None

    # --- Compute (no file I/O) --------------------------------------
    computed = compute_triage_eval(
        sid=sid,
        cases_dir=cases_dir,
        case_ids=case_ids,
        by_case=by_case,
        strategies=strategies,
        k_list=k_list,
        max_k=max_k,
        cal=cal,
        include_tool_marginal=req.include_tool_marginal,
    )

    # --- Assemble summary JSON --------------------------------------
    summary: Dict[str, Any] = {
        "suite_id": sid,
        "suite_dir": str(suite_dir),
        "dataset_csv": str(dataset_csv),
        "built_at": _now_iso(),
        "ks": list(k_list),
        "strategies": list(strategies.keys()),
        "cases_total": int(len(case_ids)),
        "cases_with_gt": int(len(computed.cases_with_gt)),
        "cases_without_gt": int(len(computed.cases_without_gt)),
        "cases_no_clusters": list(computed.cases_no_clusters),
        "cases_with_gt_but_no_clusters": list(computed.cases_with_gt_but_no_clusters),
        "cases_with_gt_but_no_overlaps": list(computed.cases_with_gt_but_no_overlaps),
        "macro": computed.macro,
        "micro": computed.micro,
        "delta_vs_baseline": computed.delta_vs_baseline,
        "topk_focus": computed.topk_focus,
        "calibration_context": computed.calibration_context,
        "out_by_case_csv": str(paths.out_by_case_csv),
        "out_summary_json": str(paths.out_summary_json),
        "out_tool_utility_csv": str(paths.out_tool_csv),
        "out_tool_marginal_csv": (str(paths.out_tool_marginal_csv) if computed.tool_marginal_rows else ""),
        "out_topk_csv": str(paths.out_topk_csv),
        "out_deltas_by_case_csv": (str(paths.out_deltas_by_case_csv) if computed.deltas_by_case_rows else ""),
        "out_readme_md": "" if readme_path is None else str(readme_path),
    }

    # --- Write outputs ----------------------------------------------
    write_tables_and_summary(
        req=req,
        paths=paths,
        computed=computed,
        summary=summary,
        warnings=warnings,
    )

    return summary
