"""pipeline.analysis.suite_triage_eval

Suite-level evaluation for triage rankings.

Purpose
-------
Given a suite-wide cluster dataset (triage_dataset.csv), compute simple,
engineering-friendly metrics to compare different ranking strategies and
quantify tool contribution.

This is intentionally filesystem-first, deterministic, and explainable.

Inputs
------
- runs/suites/<suite_id>/analysis/_tables/triage_dataset.csv
- runs/suites/<suite_id>/cases/<case_id>/gt/gt_score.json (optional; only when GT exists)

Outputs
-------
Written under runs/suites/<suite_id>/analysis/_tables/:

- triage_eval_by_case.csv
    Per-case metrics by strategy and K.

- triage_eval_summary.json
    Suite-level macro and micro averages by strategy and K.

- triage_tool_utility.csv
    Tool contribution summary:
      - gt_ids_covered / unique_gt_ids (marginal GT recall)
      - neg_clusters / exclusive_neg_clusters (noise attribution)

Notes
-----
- "macro" averages treat each case equally.
- "micro" averages pool numerators/denominators across cases.
- Cases without GT are excluded from GT-based metrics.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from pipeline.analysis.io.write_artifacts import write_csv, write_json
from pipeline.analysis.suite_triage_calibration import (
    load_triage_calibration,
    tool_weights_from_calibration,
    triage_score_v1,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()




def _write_triage_eval_readme(out_tables: Path, *, suite_id: str, ks: Sequence[int]) -> Path:
    """Write a small README next to triage eval artifacts.

    This keeps metric definitions (especially K) discoverable alongside
    generated outputs.
    """

    readme_path = Path(out_tables) / "README_triage_eval.md"
    readme_path.parent.mkdir(parents=True, exist_ok=True)

    ks_str = ", ".join(str(k) for k in ks)
    built_at = _now_iso()

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
- triage_eval_topk.csv: top-ranked clusters per case/strategy (up to max(K))
"""

    readme_path.write_text(content, encoding="utf-8")
    return readme_path
def _to_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return int(default)
        if isinstance(x, bool):
            return int(x)
        return int(float(str(x)))
    except Exception:
        return int(default)


def _to_float(x: Any, default: float = 0.0) -> float:
    try:
        if x is None:
            return float(default)
        return float(str(x))
    except Exception:
        return float(default)


def _parse_json_list(raw: str) -> List[str]:
    if not raw:
        return []
    try:
        v = json.loads(raw)
        if isinstance(v, list):
            return [str(x) for x in v]
    except Exception:
        return []
    return []


def _parse_semicolon_list(raw: str) -> List[str]:
    if not raw:
        return []
    parts = [p.strip() for p in str(raw).split(";")]
    return [p for p in parts if p]


def _load_csv_rows(path: Path) -> List[Dict[str, str]]:
    with Path(path).open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [dict(r) for r in reader if isinstance(r, dict)]


def _case_dirs(cases_dir: Path) -> List[Path]:
    if not cases_dir.exists():
        return []
    out = [p for p in cases_dir.iterdir() if p.is_dir()]
    out.sort(key=lambda p: p.name)
    return out


def _load_case_gt_ids(case_dir: Path) -> Tuple[Set[str], bool]:
    """Return (gt_ids, has_gt).

    has_gt is False if gt_score.json is missing or contains no GT ids.
    """
    p = Path(case_dir) / "gt" / "gt_score.json"
    if not p.exists():
        return set(), False
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return set(), False

    rows: Any = None
    if isinstance(data, dict):
        rows = data.get("rows")
    elif isinstance(data, list):
        rows = data

    if not isinstance(rows, list):
        return set(), False

    gt_ids: Set[str] = set()
    for r in rows:
        if not isinstance(r, dict):
            continue
        gid = r.get("gt_id") or r.get("id")
        if gid:
            gt_ids.add(str(gid))

    return gt_ids, bool(gt_ids)


def _key_file_path(r: Dict[str, str]) -> str:
    return str(r.get("file_path") or "")


def _key_start_line(r: Dict[str, str]) -> int:
    return _to_int(r.get("start_line"), 0)


def _rank_baseline(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Baseline ranking.

    Prefer triage_rank if present. Otherwise, mirror triage_queue tie-breaks.
    """
    # If at least one row has a positive triage_rank, use it.
    any_rank = any(_to_int(r.get("triage_rank"), 0) > 0 for r in rows)
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
        ),
    )


def _load_suite_calibration(suite_dir: Path, *, out_dirname: str = "analysis") -> Optional[Dict[str, Any]]:
    """Load suite-level triage calibration if present (best-effort)."""

    p = Path(suite_dir) / out_dirname / "triage_calibration.json"
    try:
        return load_triage_calibration(p)
    except Exception:
        return None


def _rank_calibrated(rows: List[Dict[str, str]], *, cal: Mapping[str, Any]) -> List[Dict[str, str]]:
    """Calibrated ranking (v1).

    Sort primarily by triage_score_v1 desc, then fall back to the legacy
    deterministic ties (mirrors triage_queue ordering).
    """

    weights = tool_weights_from_calibration(cal)

    scoring = cal.get("scoring") if isinstance(cal, dict) else None
    agreement_lambda = float(scoring.get("agreement_lambda", 0.0)) if isinstance(scoring, dict) else 0.0
    sb = scoring.get("severity_bonus") if isinstance(scoring, dict) else None
    if not isinstance(sb, dict):
        sb = {"HIGH": 0.25, "MEDIUM": 0.10, "LOW": 0.0, "UNKNOWN": 0.0}
    sev_bonus: Dict[str, float] = {str(k).upper(): float(v) for k, v in sb.items()}

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
        ),
    )


def _gt_ids_for_row(r: Dict[str, str]) -> List[str]:
    # Canonical list encoding.
    ids = _parse_json_list(str(r.get("gt_overlap_ids_json") or ""))
    if ids:
        return ids
    # Human-readable fallback.
    return _parse_semicolon_list(str(r.get("gt_overlap_ids") or ""))


def _tools_for_row(r: Dict[str, str]) -> List[str]:
    tools = _parse_json_list(str(r.get("tools_json") or ""))
    if tools:
        return tools
    raw = str(r.get("tools") or "")
    if not raw:
        return []
    return [t.strip() for t in raw.split(",") if t.strip()]


@dataclass(frozen=True)
class CaseEval:
    case_id: str
    has_gt: bool
    gt_total: int
    n_clusters: int


def build_triage_eval(
    *,
    suite_dir: Path,
    suite_id: Optional[str] = None,
    ks: Sequence[int] = (1, 3, 5, 10, 25),
    out_dirname: str = "analysis",
    dataset_relpath: str = "analysis/_tables/triage_dataset.csv",
) -> Dict[str, Any]:
    """Compute suite-level triage evaluation metrics.

    Returns a JSON-serializable summary dict.
    """

    suite_dir = Path(suite_dir).resolve()
    if not suite_dir.exists() or not suite_dir.is_dir():
        raise FileNotFoundError(f"suite_dir not found: {suite_dir}")

    sid = str(suite_id) if suite_id else suite_dir.name

    dataset_csv = suite_dir / dataset_relpath
    if not dataset_csv.exists():
        raise FileNotFoundError(f"triage_dataset.csv not found: {dataset_csv}")

    rows = _load_csv_rows(dataset_csv)

    # Group dataset rows by case.
    by_case: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for r in rows:
        cid = str(r.get("case_id") or "").strip()
        if not cid:
            continue
        by_case[cid].append(r)

    cases_dir = suite_dir / "cases"
    case_ids = [p.name for p in _case_dirs(cases_dir)]
    if not case_ids:
        # Fall back to dataset-derived ids.
        case_ids = sorted(by_case.keys())

    strategies = {
        "baseline": _rank_baseline,
        "agreement": _rank_agreement,
    }

    # Optional suite-level calibration strategy.
    #
    # This is enabled when runs/suites/<suite_id>/analysis/triage_calibration.json exists.
    cal = _load_suite_calibration(suite_dir, out_dirname=out_dirname)
    if cal:
        # Capture cal in a default argument to keep behavior deterministic.
        def _rank_cal(rows: List[Dict[str, str]], *, _cal: Dict[str, Any] = cal) -> List[Dict[str, str]]:
            return _rank_calibrated(rows, cal=_cal)

        strategies["calibrated"] = _rank_cal

    # Normalize K values.
    k_list = sorted({int(k) for k in ks if int(k) > 0})
    if not k_list:
        k_list = [1, 3, 5, 10, 25]

    max_k = max(k_list) if k_list else 0

    out_dir = suite_dir / out_dirname
    out_tables = out_dir / "_tables"
    out_by_case_csv = out_tables / "triage_eval_by_case.csv"
    out_summary_json = out_tables / "triage_eval_summary.json"
    out_tool_csv = out_tables / "triage_tool_utility.csv"
    out_topk_csv = out_tables / "triage_eval_topk.csv"
    out_log = out_dir / "triage_eval.log"


    # Write a README explaining K/metrics next to generated artifacts (best-effort).
    readme_path: Optional[Path] = None
    try:
        readme_path = _write_triage_eval_readme(out_tables, suite_id=sid, ks=k_list)
    except Exception:
        readme_path = None

    # --- Accumulators -------------------------------------------------
    by_case_rows: List[Dict[str, Any]] = []
    cases_with_gt: List[str] = []
    cases_without_gt: List[str] = []
    cases_no_clusters: List[str] = []
    cases_with_gt_but_no_clusters: List[str] = []
    cases_with_gt_but_no_overlaps: List[str] = []

    # Drilldown: ranked rows (per case+strategy) up to max(ks)
    topk_rows: List[Dict[str, Any]] = []

    macro_prec_sum: Dict[str, Dict[int, float]] = defaultdict(lambda: defaultdict(float))
    macro_prec_n: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    micro_prec_tp: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    micro_prec_denom: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))

    macro_cov_sum: Dict[str, Dict[int, float]] = defaultdict(lambda: defaultdict(float))
    macro_cov_n: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    micro_cov_covered: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    micro_cov_total: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))

    # Tool utility
    gt_cover_tools: Dict[str, Set[str]] = defaultdict(set)
    tool_neg_clusters: Dict[str, int] = defaultdict(int)
    tool_excl_neg_clusters: Dict[str, int] = defaultdict(int)

    # --- Per-case eval -------------------------------------------------
    for case_id in case_ids:
        case_rows = list(by_case.get(case_id) or [])
        n_clusters = len(case_rows)
        if n_clusters == 0:
            cases_no_clusters.append(case_id)

        gt_ids, has_gt = _load_case_gt_ids(cases_dir / case_id)
        gt_total = len(gt_ids)
        if has_gt:
            cases_with_gt.append(case_id)
        else:
            cases_without_gt.append(case_id)


        if has_gt and n_clusters == 0:
            cases_with_gt_but_no_clusters.append(case_id)

        if has_gt and n_clusters > 0:
            any_pos = any(_to_int(r.get("gt_overlap"), 0) == 1 for r in case_rows)
            if not any_pos:
                cases_with_gt_but_no_overlaps.append(case_id)

        for strat, rank_fn in strategies.items():
            ordered = rank_fn(case_rows)

            # Drilldown rows for inspecting top-1/top-3/top-5 behavior.
            # We emit up to max_k ranks for each case+strategy.
            if max_k > 0 and ordered:
                covered_so_far: Set[str] = set()
                max_rank = min(int(max_k), len(ordered))
                for idx, r in enumerate(ordered[:max_rank], start=1):
                    ids = _gt_ids_for_row(r) if has_gt else []
                    if has_gt and gt_total:
                        covered_so_far.update(ids)
                        cum_cov: Optional[float] = float(len(covered_so_far)) / float(gt_total)
                    else:
                        cum_cov = None

                    topk_rows.append(
                        {
                            "suite_id": sid,
                            "case_id": case_id,
                            "strategy": strat,
                            "rank": int(idx),
                            "cluster_id": str(r.get("cluster_id") or ""),
                            "tool_count": _to_int(r.get("tool_count"), 0),
                            "tools_json": str(r.get("tools_json") or ""),
                            "tools": str(r.get("tools") or ""),
                            "max_severity": str(r.get("max_severity") or ""),
                            "max_severity_rank": _to_int(r.get("max_severity_rank"), 0),
                            "finding_count": _to_int(r.get("finding_count"), 0),
                            "file_path": str(r.get("file_path") or ""),
                            "start_line": _to_int(r.get("start_line"), 0),
                            "triage_rank": _to_int(r.get("triage_rank"), 0),
                            "triage_score_v1": str(r.get("triage_score_v1") or ""),
                            "gt_overlap": _to_int(r.get("gt_overlap"), 0),
                            "gt_overlap_ids_json": str(r.get("gt_overlap_ids_json") or ""),
                            "gt_overlap_ids": str(r.get("gt_overlap_ids") or ""),
                            "gt_overlap_ids_count": int(len(ids)),
                            "has_gt": int(bool(has_gt)),
                            "gt_total": int(gt_total),
                            "cumulative_gt_covered": "" if cum_cov is None else int(len(covered_so_far)),
                            "cumulative_gt_coverage": "" if cum_cov is None else round(float(cum_cov), 6),
                        }
                    )

            for k in k_list:
                k_eff = min(k, len(ordered))
                top = ordered[:k_eff]

                # Precision@K
                tp = sum(1 for r in top if _to_int(r.get("gt_overlap"), 0) == 1) if has_gt else 0
                denom = int(k_eff) if has_gt else 0
                prec = (float(tp) / float(denom)) if denom else None

                # Coverage@K
                covered_ids: Set[str] = set()
                if has_gt and gt_total:
                    for r in top:
                        covered_ids.update(_gt_ids_for_row(r))
                covered = len(covered_ids) if (has_gt and gt_total) else 0
                cov = (float(covered) / float(gt_total)) if (has_gt and gt_total) else None

                by_case_rows.append(
                    {
                        "suite_id": sid,
                        "case_id": case_id,
                        "strategy": strat,
                        "k": int(k),
                        "n_clusters": int(n_clusters),
                        "has_gt": int(bool(has_gt)),
                        "gt_total": int(gt_total),
                        "precision": "" if prec is None else round(float(prec), 6),
                        "tp_at_k": int(tp),
                        "denom_at_k": int(denom),
                        "gt_coverage": "" if cov is None else round(float(cov), 6),
                        "gt_covered_at_k": int(covered),
                    }
                )

                # Aggregate only cases with GT.
                if has_gt and denom:
                    macro_prec_sum[strat][k] += float(tp) / float(denom)
                    macro_prec_n[strat][k] += 1
                    micro_prec_tp[strat][k] += int(tp)
                    micro_prec_denom[strat][k] += int(denom)

                if has_gt and gt_total:
                    macro_cov_sum[strat][k] += float(covered) / float(gt_total)
                    macro_cov_n[strat][k] += 1
                    micro_cov_covered[strat][k] += int(covered)
                    micro_cov_total[strat][k] += int(gt_total)

        # Tool utility attribution only for cases with GT (avoid treating "no GT" as negatives).
        if has_gt:
            for r in case_rows:
                tools = _tools_for_row(r)
                if _to_int(r.get("gt_overlap"), 0) == 1:
                    for gid in _gt_ids_for_row(r):
                        gt_cover_tools[gid].update(set(tools))
                else:
                    # gt_overlap==0 (negative) attribution
                    if tools:
                        for t in tools:
                            tool_neg_clusters[t] += 1
                        if len(tools) == 1:
                            tool_excl_neg_clusters[tools[0]] += 1

    # --- Suite summary --------------------------------------------------
    def _safe_div(num: int, den: int) -> Optional[float]:
        if den <= 0:
            return None
        return float(num) / float(den)

    macro: Dict[str, Dict[str, Dict[str, Any]]] = {}
    micro: Dict[str, Dict[str, Dict[str, Any]]] = {}

    for strat in strategies.keys():
        macro[strat] = {}
        micro[strat] = {}
        for k in k_list:
            # Macro averages
            p_n = macro_prec_n[strat].get(k, 0)
            p_sum = macro_prec_sum[strat].get(k, 0.0)
            c_n = macro_cov_n[strat].get(k, 0)
            c_sum = macro_cov_sum[strat].get(k, 0.0)

            macro[strat][str(k)] = {
                "precision": None if p_n == 0 else round(float(p_sum) / float(p_n), 6),
                "precision_cases": int(p_n),
                "gt_coverage": None if c_n == 0 else round(float(c_sum) / float(c_n), 6),
                "gt_coverage_cases": int(c_n),
            }

            # Micro averages
            tp = micro_prec_tp[strat].get(k, 0)
            denom = micro_prec_denom[strat].get(k, 0)
            covered = micro_cov_covered[strat].get(k, 0)
            total_gt = micro_cov_total[strat].get(k, 0)

            micro[strat][str(k)] = {
                "precision": None if denom == 0 else round(float(tp) / float(denom), 6),
                "tp_at_k": int(tp),
                "denom_at_k": int(denom),
                "gt_coverage": None if total_gt == 0 else round(float(covered) / float(total_gt), 6),
                "gt_covered_at_k": int(covered),
                "gt_total": int(total_gt),
            }

    # --- Tool utility ---------------------------------------------------
    unique_gt_by_tool: Dict[str, int] = defaultdict(int)
    total_gt_by_tool: Dict[str, int] = defaultdict(int)
    for gid, tools in gt_cover_tools.items():
        for t in tools:
            total_gt_by_tool[t] += 1
        if len(tools) == 1:
            unique_gt_by_tool[next(iter(tools))] += 1

    all_tools = sorted(set(list(total_gt_by_tool.keys()) + list(tool_neg_clusters.keys())))
    tool_rows: List[Dict[str, Any]] = []
    for t in all_tools:
        tool_rows.append(
            {
                "suite_id": sid,
                "tool": t,
                "gt_ids_covered": int(total_gt_by_tool.get(t, 0)),
                "unique_gt_ids": int(unique_gt_by_tool.get(t, 0)),
                "neg_clusters": int(tool_neg_clusters.get(t, 0)),
                "exclusive_neg_clusters": int(tool_excl_neg_clusters.get(t, 0)),
            }
        )

    # --- Write outputs --------------------------------------------------
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

    summary: Dict[str, Any] = {
        "suite_id": sid,
        "suite_dir": str(suite_dir),
        "dataset_csv": str(dataset_csv),
        "built_at": _now_iso(),
        "ks": list(k_list),
        "strategies": list(strategies.keys()),
        "cases_total": int(len(case_ids)),
        "cases_with_gt": int(len(cases_with_gt)),
        "cases_without_gt": int(len(cases_without_gt)),
        "cases_no_clusters": list(cases_no_clusters),
        "cases_with_gt_but_no_clusters": list(cases_with_gt_but_no_clusters),
        "cases_with_gt_but_no_overlaps": list(cases_with_gt_but_no_overlaps),
        "macro": macro,
        "micro": micro,
        "out_by_case_csv": str(out_by_case_csv),
        "out_summary_json": str(out_summary_json),
        "out_tool_utility_csv": str(out_tool_csv),
        "out_topk_csv": str(out_topk_csv),
        "out_readme_md": "" if readme_path is None else str(readme_path),
    }

    write_json(out_summary_json, summary)

    # Best-effort log for missing GT / empty cases.
    try:
        lines: List[str] = []
        lines.append(f"[{summary['built_at']}] triage_eval build")
        lines.append(f"suite_id        : {sid}")
        lines.append(f"dataset_csv     : {dataset_csv}")
        lines.append(f"cases_total     : {len(case_ids)}")
        lines.append(f"cases_with_gt   : {len(cases_with_gt)}")
        lines.append(f"cases_without_gt: {len(cases_without_gt)}")
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

    return summary
