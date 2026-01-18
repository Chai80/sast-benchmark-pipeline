from __future__ import annotations

from pathlib import Path
from typing import Optional

from cli.common import parse_csv
from pipeline.models import CaseSpec
from pipeline.orchestrator import RunRequest
from pipeline.pipeline import SASTBenchmarkPipeline
from pipeline.scanners import DEFAULT_SCANNERS_CSV, SUPPORTED_SCANNERS


def run_benchmark(
    args,
    pipeline: SASTBenchmarkPipeline,
    *,
    case: CaseSpec,
    repo_id: str,
    suite_root: Path,
    suite_id: Optional[str],
) -> int:
    scanners_csv = args.scanners or DEFAULT_SCANNERS_CSV
    scanners = [s for s in parse_csv(scanners_csv) if s in SUPPORTED_SCANNERS]

    req = RunRequest(
        invocation_mode="benchmark",
        case=case,
        repo_id=repo_id,
        scanners=scanners,
        suite_root=suite_root,
        suite_id=suite_id,
        use_suite=True,
        dry_run=bool(args.dry_run),
        quiet=bool(args.quiet),
        skip_analysis=bool(args.skip_analysis),
        tolerance=int(args.tolerance),
        gt_tolerance=int(getattr(args, "gt_tolerance", 0)),
        gt_source=str(getattr(args, "gt_source", "auto")),
        analysis_filter=str(args.analysis_filter),
        exclude_prefixes=getattr(args, "exclude_prefixes", ()) or (),
        include_harness=bool(getattr(args, "include_harness", False)),
        sonar_project_key=args.sonar_project_key,
        aikido_git_ref=args.aikido_git_ref,
        argv=None,
        python_executable=None,
    )

    return int(pipeline.run(req))
