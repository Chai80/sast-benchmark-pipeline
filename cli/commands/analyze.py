from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from cli.common import parse_csv
from pipeline.analysis.io.case_index import write_case_index_json
from pipeline.analysis.io.meta import read_json_if_exists
from pipeline.models import CaseSpec, RepoSpec
from pipeline.orchestrator import AnalyzeRequest
from pipeline.pipeline import SASTBenchmarkPipeline
from pipeline.scanners import DEFAULT_SCANNERS_CSV, SUPPORTED_SCANNERS


def _parse_tools(args) -> list[str]:
    tools_csv = args.tools or DEFAULT_SCANNERS_CSV
    return [t for t in parse_csv(tools_csv) if t in SUPPORTED_SCANNERS]


def _as_dict(x: Any) -> dict:
    return x if isinstance(x, dict) else {}


def _case_spec_from_case_dir(
    case_dir: Path, *, default_track: Optional[str] = None
) -> CaseSpec:
    """Best-effort reconstruct a CaseSpec from <case_dir>/case.json.

    Analysis is mostly independent of repo identity, but using the recorded
    runs_repo_name improves compatibility with legacy layouts.
    """

    case_dir = Path(case_dir)
    case_id = case_dir.name

    raw = read_json_if_exists(case_dir / "case.json") or {}
    repo_obj = _as_dict(raw.get("repo"))
    case_obj = _as_dict(raw.get("case"))

    runs_repo_name = str(repo_obj.get("runs_repo_name") or "").strip() or case_id
    label = str(repo_obj.get("label") or "").strip() or runs_repo_name

    repo_url = str(repo_obj.get("repo_url") or "").strip() or None
    repo_path = str(repo_obj.get("repo_path") or "").strip() or None

    branch = str(repo_obj.get("git_branch") or "").strip() or None
    commit = str(repo_obj.get("git_commit") or "").strip() or None

    track = str(case_obj.get("track") or "").strip() or (
        str(default_track).strip() if default_track else None
    )

    tags_any = case_obj.get("tags")
    tags = dict(tags_any) if isinstance(tags_any, dict) else {}

    return CaseSpec(
        case_id=case_id,
        runs_repo_name=runs_repo_name,
        label=label,
        repo=RepoSpec(repo_key=None, repo_url=repo_url, repo_path=repo_path),
        branch=branch,
        commit=commit,
        track=track,
        tags=tags,
    )


def _maybe_warn_gt_scoring(metric: str, gt_source: str) -> None:
    """Print a user-facing note about GT scoring scope.

    GT scoring (gt_score) is designed for benchmark/test suites where a case has
    ground-truth annotations (inline markers) or a gt_catalog.yaml. When running
    analysis on real repos without GT, users should disable it explicitly.
    """

    metric_s = str(metric or "").strip().lower()
    gt_src = str(gt_source or "").strip().lower()

    if metric_s != "suite":
        return
    if gt_src in {"", "none"}:
        return

    print(
        "\nℹ️  GT scoring note: gt_score is intended for benchmark/test suites (cases with GT markers or gt_catalog.yaml)."
    )
    print(
        "    If you're analyzing a real repo without ground truth, pass --gt-source none to skip gt_score."
    )


def run_analyze(
    args,
    pipeline: SASTBenchmarkPipeline,
    *,
    case: CaseSpec,
    suite_root: Path,
    suite_id: Optional[str],
) -> int:
    metric = args.metric or "hotspots"

    _maybe_warn_gt_scoring(metric, str(getattr(args, "gt_source", "auto")))

    tools = _parse_tools(args)

    req = AnalyzeRequest(
        metric=metric,
        case=case,
        suite_root=suite_root,
        suite_id=suite_id,
        case_path=args.case_path,
        runs_dir=Path(args.runs_dir) if args.runs_dir else None,
        tools=tools,
        output_format=str(args.format),
        out=args.out,
        analysis_out_dir=args.analysis_out_dir,
        tolerance=int(args.tolerance),
        gt_tolerance=int(getattr(args, "gt_tolerance", 0)),
        gt_source=str(getattr(args, "gt_source", "auto")),
        analysis_filter=str(args.analysis_filter),
        exclude_prefixes=getattr(args, "exclude_prefixes", ()) or (),
        include_harness=bool(getattr(args, "include_harness", False)),
        max_unique=int(args.max_unique),
    )
    return int(pipeline.analyze(req))


def run_analyze_suite_all_cases(
    args,
    pipeline: SASTBenchmarkPipeline,
    *,
    suite_root: Path,
    suite_id: str,
    suite_dir: Path,
) -> int:
    """Analyze all cases in a suite (non-interactive).

    This is the enabling step for the calibration/DS layer because it ensures
    every case has analysis artifacts under cases/*/analysis/.

    Legacy behavior (analyze one case) is still available by passing --case-id.
    """

    metric = str(getattr(args, "metric", "") or "hotspots").strip()
    if metric != "suite":
        raise SystemExit(
            f"run_analyze_suite_all_cases requires --metric suite (got: {metric!r})"
        )

    _maybe_warn_gt_scoring(metric, str(getattr(args, "gt_source", "auto")))

    if getattr(args, "analysis_out_dir", None):
        # In multi-case mode, a single output dir is ambiguous and risks collisions.
        print(
            "\nWARNING: --analysis-out-dir is ignored when analyzing ALL cases in a suite."
        )
        print("         Outputs will be written to each case's <case_dir>/analysis/.")

    if getattr(args, "out", None):
        print("\nWARNING: --out is ignored when analyzing ALL cases in a suite.")

    cases_dir = Path(suite_dir) / "cases"
    if not cases_dir.exists() or not cases_dir.is_dir():
        raise SystemExit(f"Suite has no cases directory: {cases_dir}")

    case_ids = sorted([p.name for p in cases_dir.iterdir() if p.is_dir()])
    if not case_ids:
        raise SystemExit(f"No cases found in suite: {suite_dir}")

    tools = _parse_tools(args)
    overall_rc = 0

    for idx, cid in enumerate(case_ids, start=1):
        case_dir = (cases_dir / cid).resolve()
        print("\n" + "=" * 72)
        print(f"Analyze case {idx}/{len(case_ids)}: {cid}")

        case_spec = _case_spec_from_case_dir(
            case_dir, default_track=getattr(args, "track", None)
        )

        req = AnalyzeRequest(
            metric="suite",
            case=case_spec,
            suite_root=suite_root,
            suite_id=str(suite_id),
            case_path=str(case_dir),
            runs_dir=None,
            tools=tools,
            output_format=str(args.format),
            out=None,
            analysis_out_dir=None,
            tolerance=int(args.tolerance),
            gt_tolerance=int(getattr(args, "gt_tolerance", 0)),
            gt_source=str(getattr(args, "gt_source", "auto")),
            analysis_filter=str(args.analysis_filter),
            exclude_prefixes=getattr(args, "exclude_prefixes", ()) or (),
            include_harness=bool(getattr(args, "include_harness", False)),
            max_unique=int(args.max_unique),
        )

        rc = int(pipeline.analyze(req))
        overall_rc = max(overall_rc, rc)

    idx_path = write_case_index_json(Path(suite_dir), case_ids=case_ids)

    readme_path = idx_path.parent / "README.txt"

    print(f"Suite index: {idx_path}")

    if readme_path.exists():
        print(f"Suite README: {readme_path}")

    else:
        print(f"Suite README (not found): {readme_path}")

    print(f"Per-case outputs: {Path(suite_dir) / 'cases' / '<case_id>' / 'analysis'}")

    print(
        f"Case tables:     {Path(suite_dir) / 'cases' / '<case_id>' / 'analysis' / '_tables'}"
    )

    print(f"\nWrote suite case index: {idx_path}")

    return overall_rc
