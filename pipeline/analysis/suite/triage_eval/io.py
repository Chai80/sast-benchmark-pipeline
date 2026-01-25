"""pipeline.analysis.suite.triage_eval.io

Artifact writing for suite-level triage evaluation.

This module owns writing the CSV/JSON/MD artifacts produced by
``build_triage_eval``. Keeping it separate from the compute logic makes the
evaluation easier to reason about and easier to test.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence

from pipeline.analysis.io.write_artifacts import write_csv, write_json


def write_readme(
    *,
    out_tables: Path,
    suite_id: str,
    ks: Sequence[int],
) -> Path:
    """Write a small README next to triage eval artifacts.

    This keeps metric definitions (especially K) discoverable alongside
    generated outputs.
    """

    out_tables = Path(out_tables).resolve()
    out_tables.mkdir(parents=True, exist_ok=True)

    readme_path = out_tables / "README_triage_eval.md"
    ks_str = ", ".join(str(k) for k in ks)
    built_at = datetime.now(timezone.utc).isoformat()

    content = f"""# Triage evaluation artifacts

Suite: {suite_id}
Generated: {built_at}

This folder contains suite-level evaluation outputs comparing triage ranking strategies.

## What is a cluster?
A *cluster* is one triage-able unit of work: multiple tool findings that point to the same code location
(same file + nearby line range within the clustering tolerance). The triage queue ranks clusters, not raw findings.

## What is K?
*K* means: **how many top-ranked clusters a human looks at**.

Examples:
- Precision@1 answers: "Is the first item we show correct?"
- Precision@3 answers: "If I review the first 3 items, how many are real?"
- Coverage@5 answers: "By the time I review 5 items, how much of the ground truth did I surface?"

This run evaluates K values: {ks_str}

## Metrics
### Precision@K
Of the top K clusters (or all clusters if fewer than K exist), what fraction overlap ground truth?

Precision@K = (GT-positive clusters in top K) / (clusters considered)

### GT coverage@K
Ground truth items can be many-to-one with clusters. A single cluster may overlap multiple GT IDs.

Coverage@K = (unique GT IDs covered by top K clusters) / (total GT IDs for the case)

Notes:
- If a case has no GT (or GT artifacts are missing), GT-based metrics are reported as N/A for that case.
- Coverage reflects end-to-end performance (detection + ranking). If tools produce no clusters for a GT-heavy case,
  coverage will be low even if ranking is good on other cases.

## Macro vs micro averages
We report two suite-level aggregations:

- Macro average: compute the metric per case, then average across cases (each case counts equally).
- Micro average: pool numerators/denominators across cases (large cases count more).

Both are useful:
- Macro tells you if the system is consistently good across cases.
- Micro tells you overall quality across the whole suite's top-K items.

## Files
- triage_eval_by_case.csv: per-case metrics for each strategy and K
- triage_eval_summary.json: suite-level macro/micro summaries + warnings
- triage_tool_utility.csv: tool contribution (unique GT coverage) vs noise (exclusive negatives)
- triage_tool_marginal.csv: drop-one tool marginal value (micro Precision@K / Coverage@K deltas)
- triage_eval_topk.csv: top-ranked clusters per case/strategy (up to max(K))
- triage_eval_deltas_by_case.csv: per-case deltas vs baseline (helps interpret lifts per case)
"""

    readme_path.write_text(content, encoding="utf-8")
    return readme_path


def write_tables_and_summary(
    *,
    out_by_case_csv: Path,
    out_tool_csv: Path,
    out_tool_marginal_csv: Path,
    out_topk_csv: Path,
    out_deltas_by_case_csv: Path,
    out_summary_json: Path,
    out_log: Path,
    by_case_rows: Sequence[Dict[str, Any]],
    tool_rows: Sequence[Dict[str, Any]],
    tool_marginal_rows: Sequence[Dict[str, Any]],
    topk_rows: Sequence[Dict[str, Any]],
    deltas_by_case_rows: Sequence[Dict[str, Any]],
    summary: Dict[str, Any],
    cases_without_gt: Sequence[str],
    cases_no_clusters: Sequence[str],
    cases_with_gt_but_no_clusters: Sequence[str],
    cases_with_gt_but_no_overlaps: Sequence[str],
    out_dirname: str,
    suite_dir: Path,
    suite_id: str,
) -> None:
    """Write triage-eval output artifacts.

    Notes
    -----
    - The write order and CSV fieldnames match the prior monolithic
      implementation to keep diffs stable.
    - The optional suite report is best-effort and must never fail the eval.
    """

    write_csv(
        out_by_case_csv,
        by_case_rows,
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
        out_tool_csv,
        tool_rows,
        fieldnames=[
            "suite_id",
            "tool",
            "gt_ids_covered",
            "unique_gt_ids",
            "neg_clusters",
            "exclusive_neg_clusters",
        ],
    )

    if tool_marginal_rows:
        write_csv(
            out_tool_marginal_csv,
            tool_marginal_rows,
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
        out_topk_csv,
        topk_rows,
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

    if deltas_by_case_rows:
        write_csv(
            out_deltas_by_case_csv,
            deltas_by_case_rows,
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

    write_json(out_summary_json, summary)

    _write_best_effort_log(
        out_log=out_log,
        summary=summary,
        cases_without_gt=cases_without_gt,
        cases_no_clusters=cases_no_clusters,
        cases_with_gt_but_no_clusters=cases_with_gt_but_no_clusters,
        cases_with_gt_but_no_overlaps=cases_with_gt_but_no_overlaps,
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
    except Exception:
        pass


def _write_best_effort_log(
    *,
    out_log: Path,
    summary: Dict[str, Any],
    cases_without_gt: Sequence[str],
    cases_no_clusters: Sequence[str],
    cases_with_gt_but_no_clusters: Sequence[str],
    cases_with_gt_but_no_overlaps: Sequence[str],
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
        out_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        pass
