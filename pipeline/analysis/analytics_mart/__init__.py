"""pipeline.analysis.analytics_mart

Exports an *analytics-friendly* star schema from a suite run.

The pipeline is filesystem-first: it writes deterministic artifacts under
``runs/suites/<suite_id>/analysis`` (triage dataset/eval, calibration, etc.).

This module turns those artifacts into a small set of CSV tables that are easy
to ingest into BigQuery/Snowflake/Postgres and easy to query for:

* Data analytics deliverables (dashboards, scorecards)
* A/B testing of ranking strategies (baseline vs calibrated)
* A/B testing of tool/version changes (suite_run_id_old vs suite_run_id_new)

Output location
---------------
Writes to the suite root:

``runs/suites/<suite_id>/AnalyticsMart/``

Tables (v1)
-----------
Dimensions:
  - ``dim_suite_run.csv``: one row per suite run (metadata + signatures)
  - ``dim_case.csv``: one row per case (OWASP slice + static metadata)
  - ``dim_tool_run.csv``: one row per tool execution (provenance)

Facts:
  - ``fact_eval_case_k.csv``: case-level precision/coverage@k by strategy
  - ``fact_eval_suite_k.csv``: macro/micro KPIs by strategy@k
  - ``fact_tool_value.csv``: long-form tool contribution metrics

Design notes
------------
* CSV-only by default to avoid new dependencies.
* Best-effort: missing inputs should NOT crash the suite runbook.
* Join keys are intentionally stable:
  - ``suite_run_id`` is the suite folder name (and suite.json suite_run_id)
  - ``case_id`` is the *suite layout case folder name* (safe_name)

"""

from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from pipeline.analysis.io.config_receipts import config_signature_hash, load_scanner_config
from pipeline.analysis.io.gt_tolerance_policy import (
    read_selected_gt_tolerance,
    read_suite_json_effective_gt_tolerance,
)
from pipeline.analysis.io.meta import read_json_if_exists
from pipeline.analysis.io.write_artifacts import write_csv, write_json, write_text
from pipeline.analysis.utils.owasp import infer_owasp


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_canonical(obj: Any) -> str:
    """Deterministic JSON encoding for hashing + embedding in CSV."""

    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read_any_json(path: Path) -> Any:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


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


def _to_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return int(default)
        if isinstance(x, bool):
            return int(x)
        s = str(x).strip()
        if s == "":
            return int(default)
        return int(float(s))
    except Exception:
        return int(default)


def _to_float(x: Any, default: float = 0.0) -> float:
    try:
        if x is None:
            return float(default)
        s = str(x).strip()
        if s == "":
            return float(default)
        return float(s)
    except Exception:
        return float(default)


def _parse_number(x: Any) -> Optional[float]:
    """Best-effort parse for numeric CSV fields.

    Returns float for both ints and floats to keep the storage type simple.
    """

    s = str(x).strip() if x is not None else ""
    if not s:
        return None
    if s.lower() in {"nan", "none", "null"}:
        return None
    try:
        return float(s)
    except Exception:
        return None


def _first_existing(paths: Sequence[Path]) -> Optional[Path]:
    for p in paths:
        if Path(p).exists():
            return Path(p)
    return None


def _discover_case_dirs(suite_dir: Path) -> List[Path]:
    cases_dir = Path(suite_dir) / "cases"
    if not cases_dir.exists() or not cases_dir.is_dir():
        return []
    out = [p for p in cases_dir.iterdir() if p.is_dir()]
    out.sort(key=lambda p: p.name)
    return out


def _extract_pipeline_git_commit_from_case_manifests(case_dirs: Sequence[Path]) -> Optional[str]:
    for cd in case_dirs:
        raw = read_json_if_exists(cd / "case.json")
        if not isinstance(raw, Mapping):
            continue
        inv = raw.get("invocation")
        if not isinstance(inv, Mapping):
            continue
        env = inv.get("environment")
        if not isinstance(env, Mapping):
            continue
        sha = env.get("pipeline_git_commit")
        if isinstance(sha, str) and sha.strip():
            return sha.strip()
    return None


def _build_case_stats_from_eval(by_case_rows: Sequence[Mapping[str, Any]]) -> Dict[str, Dict[str, int]]:
    """Aggregate per-case has_gt / gt_total from triage_eval_by_case.csv."""

    out: Dict[str, Dict[str, int]] = {}
    for r in by_case_rows:
        cid = str(r.get("case_id") or "").strip()
        if not cid:
            continue
        st = out.setdefault(cid, {"has_gt": 0, "gt_total": 0})
        st["has_gt"] = max(int(st.get("has_gt", 0)), _to_int(r.get("has_gt"), 0))
        st["gt_total"] = max(int(st.get("gt_total", 0)), _to_int(r.get("gt_total"), 0))
    return out


def _read_gt_total_from_case_dir(case_dir: Path) -> Tuple[int, int]:
    """Return (has_gt, gt_total) best-effort from gt/gt_score.json."""

    gt_score = case_dir / "gt" / "gt_score.json"
    if not gt_score.exists():
        return 0, 0
    raw = _read_any_json(gt_score)
    if not isinstance(raw, Mapping):
        return 0, 0
    summ = raw.get("summary")
    if not isinstance(summ, Mapping):
        return 0, 0
    total = _to_int(summ.get("total_gt_items"), 0)
    return (1 if total > 0 else 0), int(total)


def _discover_tool_run_jsons(case_dir: Path) -> List[Path]:
    tool_runs = case_dir / "tool_runs"
    if not tool_runs.exists() or not tool_runs.is_dir():
        return []
    out = [p for p in tool_runs.rglob("run.json") if p.is_file()]
    out.sort(key=lambda p: str(p))
    return out


def _count_normalized_findings(path: Path) -> Optional[int]:
    """Best-effort count findings in a normalized.json.

    We intentionally avoid new dependencies. This loads JSON fully; for very
    large outputs this may be slower, but our benchmark suites are typically
    small and deterministic.
    """

    raw = _read_any_json(path)
    if not isinstance(raw, Mapping):
        return None
    findings = raw.get("findings")
    if isinstance(findings, list):
        return int(len(findings))
    return None


def write_analytics_mart(
    *,
    suite_dir: str | Path,
    suite_id: Optional[str] = None,
    out_dirname: str = "AnalyticsMart",
) -> Dict[str, Any]:
    """Materialize the analytics star schema for a given suite directory."""

    suite_dir = Path(suite_dir).resolve()
    suite_run_id = str(suite_id or suite_dir.name)

    analysis_dir = suite_dir / "analysis"
    tables_dir = analysis_dir / "_tables"

    # Inputs (best-effort): triage_eval + tool utility + calibration.
    triage_by_case_csv = tables_dir / "triage_eval_by_case.csv"
    triage_summary_json = tables_dir / "triage_eval_summary.json"
    triage_tool_utility_csv = tables_dir / "triage_tool_utility.csv"
    triage_tool_marginal_csv = tables_dir / "triage_tool_marginal.csv"

    triage_calibration_json = analysis_dir / "triage_calibration.json"

    suite_json = read_json_if_exists(suite_dir / "suite.json") or {}
    if not isinstance(suite_json, Mapping):
        suite_json = {}

    plan = suite_json.get("plan") if isinstance(suite_json.get("plan"), Mapping) else {}
    plan = plan if isinstance(plan, Mapping) else {}

    suite_kind_raw = str(suite_json.get("suite_kind") or "")
    benchmark_id = str(plan.get("workload_id") or suite_kind_raw or suite_run_id)
    suite_kind = str(suite_kind_raw or plan.get("suite_kind") or "")

    plan_analysis = plan.get("analysis") if isinstance(plan.get("analysis"), Mapping) else {}
    plan_analysis = plan_analysis if isinstance(plan_analysis, Mapping) else {}

    # Manifests
    qa_manifest_path = _first_existing(
        [analysis_dir / "qa_manifest.json", analysis_dir / "qa_calibration_manifest.json"]
    )
    qa_manifest = read_json_if_exists(qa_manifest_path) if qa_manifest_path else None

    # Expected scanners (for scanner_config hashing).
    scanners: List[str] = []
    try:
        if isinstance(qa_manifest, Mapping):
            inputs = qa_manifest.get("inputs")
            if isinstance(inputs, Mapping) and isinstance(inputs.get("scanners"), list):
                scanners = [str(x).strip() for x in inputs.get("scanners") or [] if str(x).strip()]
        if not scanners and isinstance(plan.get("scanners"), list):
            scanners = [str(x).strip() for x in plan.get("scanners") or [] if str(x).strip()]
    except Exception:
        scanners = []

    scanner_config = load_scanner_config(
        suite_dir=suite_dir,
        qa_manifest=qa_manifest,
        suite_json=suite_json,
        scanners=scanners,
    )
    toolset_signature = _sha256_text(_json_canonical(scanner_config))

    # Calibration signature.
    calibration_id = ""
    if triage_calibration_json.exists():
        cal_obj = _read_any_json(triage_calibration_json)
        calibration_id = _sha256_text(_json_canonical(cal_obj)) if cal_obj is not None else ""

    # GT tolerance (suite-scoped).
    gt_tol = read_selected_gt_tolerance(suite_dir=suite_dir)
    if gt_tol is None:
        gt_tol = read_suite_json_effective_gt_tolerance(suite_dir=suite_dir)

    # Case dirs + pipeline git commit.
    case_dirs = _discover_case_dirs(suite_dir)
    pipeline_git_commit = _extract_pipeline_git_commit_from_case_manifests(case_dirs) or ""

    # Load eval artifacts (facts) if present.
    by_case_rows_raw = _load_csv_rows(triage_by_case_csv)
    case_stats = _build_case_stats_from_eval(by_case_rows_raw)

    eval_summary = _read_any_json(triage_summary_json) if triage_summary_json.exists() else None

    # ------------------------------------------------------------------
    # Output dir + manifest
    # ------------------------------------------------------------------
    out_dir = (suite_dir / out_dirname).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    outputs: Dict[str, str] = {}
    warnings: List[str] = []

    # ------------------------------------------------------------------
    # dim_suite_run
    # ------------------------------------------------------------------
    dim_suite_run_path = out_dir / "dim_suite_run.csv"
    dim_suite_run_row: Dict[str, Any] = {
        "suite_run_id": suite_run_id,
        "benchmark_id": benchmark_id,
        "suite_kind": suite_kind,
        "created_at": str(suite_json.get("created_at") or "") if isinstance(suite_json, Mapping) else "",
        "updated_at": str(suite_json.get("updated_at") or "") if isinstance(suite_json, Mapping) else "",
        "run_ts_utc": str(suite_json.get("created_at") or suite_json.get("updated_at") or "")
        if isinstance(suite_json, Mapping)
        else "",
        "pipeline_git_commit": pipeline_git_commit,
        "analysis_tolerance": _to_int(plan_analysis.get("tolerance"), 0),
        "analysis_filter": str(plan_analysis.get("filter") or ""),
        "gt_tolerance_effective": ("" if gt_tol is None else int(gt_tol)),
        "scanners_json": _json_canonical(sorted(set(scanners))),
        "toolset_signature": toolset_signature,
        "calibration_id": calibration_id,
        "scanner_config_json": _json_canonical(scanner_config),
    }

    write_csv(
        dim_suite_run_path,
        [dim_suite_run_row],
        fieldnames=list(dim_suite_run_row.keys()),
    )
    outputs["dim_suite_run"] = str(dim_suite_run_path)

    # ------------------------------------------------------------------
    # dim_case
    # ------------------------------------------------------------------
    dim_case_path = out_dir / "dim_case.csv"
    dim_case_rows: List[Dict[str, Any]] = []
    for cd in case_dirs:
        case_manifest = read_json_if_exists(cd / "case.json")
        case_obj = case_manifest.get("case") if isinstance(case_manifest, Mapping) else {}
        case_obj = case_obj if isinstance(case_obj, Mapping) else {}
        repo_obj = case_manifest.get("repo") if isinstance(case_manifest, Mapping) else {}
        repo_obj = repo_obj if isinstance(repo_obj, Mapping) else {}

        cid = str((case_manifest or {}).get("case_id") or cd.name).strip()
        if not cid:
            cid = cd.name

        track = str(case_obj.get("track") or "")
        tags_obj = case_obj.get("tags")
        tags_json = _json_canonical(tags_obj) if tags_obj is not None else ""

        label = str(case_obj.get("label") or "")
        branch = str(case_obj.get("branch") or "")

        # infer_owasp(...) expects a single text blob to match against.
        o_text = " ".join([cid, branch, label, tags_json]).strip()
        o = infer_owasp(o_text)
        owasp_id, owasp_title = (o if o is not None else ("", ""))

        # Prefer suite-level eval stats; fall back to gt_score.json.
        st = case_stats.get(cid) or {}
        has_gt = int(st.get("has_gt", 0))
        gt_total = int(st.get("gt_total", 0))
        if gt_total == 0:
            has_gt2, gt_total2 = _read_gt_total_from_case_dir(cd)
            has_gt = max(has_gt, has_gt2)
            gt_total = max(gt_total, gt_total2)

        dim_case_rows.append(
            {
                "benchmark_id": benchmark_id,
                "case_id": cid,
                "case_dir": str(cd.relative_to(suite_dir)),
                "owasp_id": owasp_id,
                "owasp_title": owasp_title,
                "track": track,
                "has_gt": has_gt,
                "gt_total": gt_total,
                "repo_label": str((case_manifest or {}).get("repo_label") or "")
                if isinstance(case_manifest, Mapping)
                else "",
                "runs_repo_name": str(repo_obj.get("runs_repo_name") or ""),
                "expected_branch": str(repo_obj.get("expected_branch") or ""),
                "expected_commit": str(repo_obj.get("expected_commit") or ""),
                "tags_json": tags_json,
            }
        )

    if dim_case_rows:
        fieldnames = list(dim_case_rows[0].keys())
        write_csv(dim_case_path, dim_case_rows, fieldnames=fieldnames)
        outputs["dim_case"] = str(dim_case_path)
    else:
        warnings.append("dim_case: no case directories discovered")

    # ------------------------------------------------------------------
    # fact_eval_case_k (from triage_eval_by_case.csv)
    # ------------------------------------------------------------------
    fact_eval_case_k_path = out_dir / "fact_eval_case_k.csv"
    fact_eval_case_k_rows: List[Dict[str, Any]] = []
    if by_case_rows_raw:
        for r in by_case_rows_raw:
            fact_eval_case_k_rows.append(
                {
                    "suite_run_id": suite_run_id,
                    "benchmark_id": benchmark_id,
                    "case_id": str(r.get("case_id") or ""),
                    "strategy": str(r.get("strategy") or ""),
                    "k": _to_int(r.get("k"), 0),
                    "n_clusters": _to_int(r.get("n_clusters"), 0),
                    "has_gt": _to_int(r.get("has_gt"), 0),
                    "gt_total": _to_int(r.get("gt_total"), 0),
                    "precision_at_k": _to_float(r.get("precision"), 0.0),
                    "tp_at_k": _to_int(r.get("tp_at_k"), 0),
                    "denom_at_k": _to_int(r.get("denom_at_k"), 0),
                    "coverage_at_k": _to_float(r.get("gt_coverage"), 0.0),
                    "gt_covered_at_k": _to_int(r.get("gt_covered_at_k"), 0),
                }
            )

        fact_eval_case_k_rows.sort(
            key=lambda x: (
                str(x.get("case_id") or ""),
                str(x.get("strategy") or ""),
                int(x.get("k") or 0),
            )
        )
        write_csv(
            fact_eval_case_k_path,
            fact_eval_case_k_rows,
            fieldnames=list(fact_eval_case_k_rows[0].keys()),
        )
        outputs["fact_eval_case_k"] = str(fact_eval_case_k_path)
    else:
        warnings.append("fact_eval_case_k: missing triage_eval_by_case.csv")

    # ------------------------------------------------------------------
    # fact_eval_suite_k (from triage_eval_summary.json)
    # ------------------------------------------------------------------
    fact_eval_suite_k_path = out_dir / "fact_eval_suite_k.csv"
    fact_eval_suite_k_rows: List[Dict[str, Any]] = []
    if isinstance(eval_summary, Mapping):
        for agg_type in ("macro", "micro"):
            agg_obj = eval_summary.get(agg_type)
            if not isinstance(agg_obj, Mapping):
                continue
            for strategy, ks_obj in agg_obj.items():
                if not isinstance(ks_obj, Mapping):
                    continue
                for k_str, m in ks_obj.items():
                    if not isinstance(m, Mapping):
                        continue
                    row: Dict[str, Any] = {
                        "suite_run_id": suite_run_id,
                        "benchmark_id": benchmark_id,
                        "agg_type": str(agg_type),
                        "strategy": str(strategy),
                        "k": _to_int(k_str, 0),
                        "precision_at_k": _to_float(m.get("precision"), 0.0),
                        "coverage_at_k": _to_float(m.get("gt_coverage"), 0.0),
                        "precision_cases": _to_int(m.get("precision_cases"), 0),
                        "coverage_cases": _to_int(m.get("gt_coverage_cases"), 0),
                        "tp_at_k": _to_int(m.get("tp_at_k"), 0),
                        "denom_at_k": _to_int(m.get("denom_at_k"), 0),
                        "gt_covered_at_k": _to_int(m.get("gt_covered_at_k"), 0),
                        "gt_total": _to_int(m.get("gt_total"), 0),
                    }
                    fact_eval_suite_k_rows.append(row)

    if fact_eval_suite_k_rows:
        fact_eval_suite_k_rows.sort(
            key=lambda x: (
                str(x.get("agg_type") or ""),
                str(x.get("strategy") or ""),
                int(x.get("k") or 0),
            )
        )
        write_csv(
            fact_eval_suite_k_path,
            fact_eval_suite_k_rows,
            fieldnames=list(fact_eval_suite_k_rows[0].keys()),
        )
        outputs["fact_eval_suite_k"] = str(fact_eval_suite_k_path)
    else:
        warnings.append("fact_eval_suite_k: missing or invalid triage_eval_summary.json")

    # ------------------------------------------------------------------
    # dim_tool_run (provenance)
    # ------------------------------------------------------------------
    dim_tool_run_path = out_dir / "dim_tool_run.csv"
    dim_tool_run_rows: List[Dict[str, Any]] = []
    for cd in case_dirs:
        cid = cd.name
        for run_json_path in _discover_tool_run_jsons(cd):
            run_dir = run_json_path.parent
            run_obj = _read_any_json(run_json_path)
            if not isinstance(run_obj, Mapping):
                continue

            tool = str(run_obj.get("tool") or "")
            run_id = str(run_obj.get("run_id") or run_dir.name)
            profile = str(run_obj.get("profile") or "")

            artifacts = run_obj.get("artifacts") if isinstance(run_obj.get("artifacts"), Mapping) else {}
            artifacts = artifacts if isinstance(artifacts, Mapping) else {}

            metadata_name = artifacts.get("metadata") or "metadata.json"
            config_receipt_name = artifacts.get("config_receipt") or "config_receipt.json"
            normalized_name = artifacts.get("normalized") or "normalized.json"

            meta_path = run_dir / str(metadata_name) if metadata_name else None
            meta = _read_any_json(meta_path) if meta_path and meta_path.exists() else None
            meta = meta if isinstance(meta, Mapping) else {}

            conf_path = run_dir / str(config_receipt_name) if config_receipt_name else None
            conf = _read_any_json(conf_path) if conf_path and conf_path.exists() else None
            conf = conf if isinstance(conf, Mapping) else None

            config_receipt_sig = config_signature_hash(conf) if isinstance(conf, Mapping) else ""

            norm_path = run_dir / str(normalized_name) if normalized_name else None
            norm_findings = _count_normalized_findings(norm_path) if norm_path and norm_path.exists() else None

            dim_tool_run_rows.append(
                {
                    "suite_run_id": suite_run_id,
                    "benchmark_id": benchmark_id,
                    "case_id": cid,
                    "tool": tool,
                    "run_id": run_id,
                    "profile": profile,
                    "scanner_version": str(meta.get("scanner_version") or ""),
                    "config_hash": str(meta.get("config_hash") or ""),
                    "config_receipt_hash": config_receipt_sig,
                    "exit_code": _to_int(run_obj.get("exit_code"), 0),
                    "started": str(run_obj.get("started") or ""),
                    "finished": str(run_obj.get("finished") or ""),
                    "scan_time_seconds": _to_float(meta.get("scan_time_seconds"), 0.0),
                    "normalized_findings": ("" if norm_findings is None else int(norm_findings)),
                    "run_dir": str(run_dir.relative_to(suite_dir)),
                }
            )

    if dim_tool_run_rows:
        dim_tool_run_rows.sort(
            key=lambda x: (
                str(x.get("case_id") or ""),
                str(x.get("tool") or ""),
                str(x.get("run_id") or ""),
            )
        )
        write_csv(
            dim_tool_run_path,
            dim_tool_run_rows,
            fieldnames=list(dim_tool_run_rows[0].keys()),
        )
        outputs["dim_tool_run"] = str(dim_tool_run_path)
    else:
        warnings.append("dim_tool_run: no run.json discovered under cases/*/tool_runs")

    # ------------------------------------------------------------------
    # fact_tool_value (long-form metrics)
    # ------------------------------------------------------------------
    fact_tool_value_path = out_dir / "fact_tool_value.csv"
    fact_tool_value_rows: List[Dict[str, Any]] = []

    # Tool utility (one row per tool in source; becomes 4 rows per tool here).
    tool_utility_rows = _load_csv_rows(triage_tool_utility_csv)
    if tool_utility_rows:
        for r in tool_utility_rows:
            tool = str(r.get("tool") or "").strip()
            if not tool:
                continue
            for metric, raw_val in (
                ("gt_ids_covered", r.get("gt_ids_covered")),
                ("unique_gt_ids", r.get("unique_gt_ids")),
                ("neg_clusters", r.get("neg_clusters")),
                ("exclusive_neg_clusters", r.get("exclusive_neg_clusters")),
            ):
                val = _parse_number(raw_val)
                if val is None:
                    continue
                fact_tool_value_rows.append(
                    {
                        "suite_run_id": suite_run_id,
                        "benchmark_id": benchmark_id,
                        "tool": tool,
                        "metric_group": "utility",
                        "strategy": "",
                        "k": "",
                        "metric_name": f"utility.{metric}",
                        "metric_value": val,
                    }
                )
    else:
        warnings.append("fact_tool_value: missing triage_tool_utility.csv")

    # Tool marginal value (optional; emits many metrics).
    tool_marginal_rows = _load_csv_rows(triage_tool_marginal_csv)
    if tool_marginal_rows:
        for r in tool_marginal_rows:
            tool = str(r.get("tool") or "").strip()
            strat = str(r.get("strategy") or "").strip()
            k = _to_int(r.get("k"), 0)
            if not tool or not strat or k <= 0:
                continue
            for key, raw_val in r.items():
                if key in {"suite_id", "tool", "strategy", "k"}:
                    continue
                val = _parse_number(raw_val)
                if val is None:
                    continue
                fact_tool_value_rows.append(
                    {
                        "suite_run_id": suite_run_id,
                        "benchmark_id": benchmark_id,
                        "tool": tool,
                        "metric_group": "marginal",
                        "strategy": strat,
                        "k": k,
                        "metric_name": f"marginal.{strat}.k{k}.{key}",
                        "metric_value": val,
                    }
                )

    if fact_tool_value_rows:
        fact_tool_value_rows.sort(
            key=lambda x: (
                str(x.get("tool") or ""),
                str(x.get("metric_group") or ""),
                str(x.get("metric_name") or ""),
            )
        )
        write_csv(
            fact_tool_value_path,
            fact_tool_value_rows,
            fieldnames=list(fact_tool_value_rows[0].keys()),
        )
        outputs["fact_tool_value"] = str(fact_tool_value_path)
    else:
        warnings.append("fact_tool_value: no tool metrics emitted")

    # ------------------------------------------------------------------
    # README + manifest
    # ------------------------------------------------------------------
    readme_path = out_dir / "README.md"
    try:
        write_text(
            readme_path,
            "\n".join(
                [
                    "# AnalyticsMart (Star Schema)",
                    "",
                    "This folder is auto-generated from deterministic suite artifacts.",
                    "",
                    f"- suite_run_id: `{suite_run_id}`",
                    f"- benchmark_id: `{benchmark_id}`",
                    "",
                    "Tables:",
                    "- dim_suite_run.csv",
                    "- dim_case.csv",
                    "- dim_tool_run.csv",
                    "- fact_eval_case_k.csv",
                    "- fact_eval_suite_k.csv",
                    "- fact_tool_value.csv",
                    "",
                    "See docs/analytics_mart.md for schema + query examples.",
                    "",
                ]
            ),
        )
        outputs["README"] = str(readme_path)
    except Exception:
        # If README fails we still want the CSV exports.
        pass

    manifest = {
        "schema_version": 1,
        "built_at": _now_iso(),
        "suite_run_id": suite_run_id,
        "benchmark_id": benchmark_id,
        "out_dir": str(out_dir),
        "inputs": {
            "triage_eval_by_case_csv": str(triage_by_case_csv) if triage_by_case_csv.exists() else "",
            "triage_eval_summary_json": str(triage_summary_json) if triage_summary_json.exists() else "",
            "triage_tool_utility_csv": str(triage_tool_utility_csv) if triage_tool_utility_csv.exists() else "",
            "triage_tool_marginal_csv": str(triage_tool_marginal_csv) if triage_tool_marginal_csv.exists() else "",
            "triage_calibration_json": str(triage_calibration_json) if triage_calibration_json.exists() else "",
        },
        "outputs": outputs,
        "warnings": warnings,
    }

    manifest_path = out_dir / "analytics_mart_manifest.json"
    write_json(manifest_path, manifest)
    outputs["analytics_mart_manifest"] = str(manifest_path)

    return {
        "suite_run_id": suite_run_id,
        "benchmark_id": benchmark_id,
        "out_dir": str(out_dir),
        "outputs": outputs,
        "warnings": warnings,
    }
