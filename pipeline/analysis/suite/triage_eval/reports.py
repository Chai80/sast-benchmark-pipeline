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

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from .compute import compute_triage_eval
from .io import write_readme, write_tables_and_summary
from .load import load_strategies, load_triage_dataset, normalize_ks, resolve_case_ids


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

    suite_dir = Path(suite_dir).resolve()
    if not suite_dir.exists() or not suite_dir.is_dir():
        raise FileNotFoundError(f"suite_dir not found: {suite_dir}")

    sid = str(suite_id) if suite_id else suite_dir.name

    # --- Load inputs -------------------------------------------------
    dataset_csv, _rows, by_case = load_triage_dataset(suite_dir=suite_dir, dataset_relpath=dataset_relpath)
    cases_dir, case_ids = resolve_case_ids(suite_dir=suite_dir, by_case=by_case)
    cal, strategies = load_strategies(suite_dir=suite_dir, out_dirname=out_dirname)

    k_list = normalize_ks(ks)
    max_k = max(k_list) if k_list else 0

    # --- Resolve output paths ---------------------------------------
    out_dir = (suite_dir / out_dirname).resolve()
    out_tables = (out_dir / "_tables").resolve()
    out_tables.mkdir(parents=True, exist_ok=True)

    out_by_case_csv = out_tables / "triage_eval_by_case.csv"
    out_summary_json = out_tables / "triage_eval_summary.json"
    out_tool_csv = out_tables / "triage_tool_utility.csv"
    out_tool_marginal_csv = out_tables / "triage_tool_marginal.csv"
    out_topk_csv = out_tables / "triage_eval_topk.csv"
    out_deltas_by_case_csv = out_tables / "triage_eval_deltas_by_case.csv"
    out_log = out_tables / "triage_eval.log"

    # Small, human-friendly overview next to the tables (best-effort).
    readme_path: Optional[Path] = None
    try:
        readme_path = write_readme(out_tables=out_tables, suite_id=sid, ks=k_list)
    except Exception:
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
        include_tool_marginal=include_tool_marginal,
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
        "out_by_case_csv": str(out_by_case_csv),
        "out_summary_json": str(out_summary_json),
        "out_tool_utility_csv": str(out_tool_csv),
        "out_tool_marginal_csv": (str(out_tool_marginal_csv) if computed.tool_marginal_rows else ""),
        "out_topk_csv": str(out_topk_csv),
        "out_deltas_by_case_csv": (str(out_deltas_by_case_csv) if computed.deltas_by_case_rows else ""),
        "out_readme_md": "" if readme_path is None else str(readme_path),
    }

    # --- Write outputs ----------------------------------------------
    write_tables_and_summary(
        out_by_case_csv=out_by_case_csv,
        out_tool_csv=out_tool_csv,
        out_tool_marginal_csv=out_tool_marginal_csv,
        out_topk_csv=out_topk_csv,
        out_deltas_by_case_csv=out_deltas_by_case_csv,
        out_summary_json=out_summary_json,
        out_log=out_log,
        by_case_rows=computed.by_case_rows,
        tool_rows=computed.tool_rows,
        tool_marginal_rows=computed.tool_marginal_rows,
        topk_rows=computed.topk_rows,
        deltas_by_case_rows=computed.deltas_by_case_rows,
        summary=summary,
        cases_without_gt=computed.cases_without_gt,
        cases_no_clusters=computed.cases_no_clusters,
        cases_with_gt_but_no_clusters=computed.cases_with_gt_but_no_clusters,
        cases_with_gt_but_no_overlaps=computed.cases_with_gt_but_no_overlaps,
        out_dirname=out_dirname,
        suite_dir=suite_dir,
        suite_id=sid,
    )

    return summary
