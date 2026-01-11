from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from pipeline.models import CaseSpec
from pipeline.orchestrator import RunRequest
from pipeline.pipeline import SASTBenchmarkPipeline
from pipeline.scanners import DEFAULT_SCANNERS_CSV, SUPPORTED_SCANNERS


def _parse_csv(raw: Optional[str]) -> list[str]:
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def run_benchmark(
    args,
    pipeline: SASTBenchmarkPipeline,
    *,
    case: CaseSpec,
    repo_id: str,
    suite_root: Path,
    suite_id: Optional[str],
) -> int:
    scanners_arg = args.scanners or DEFAULT_SCANNERS_CSV
    scanners = [s for s in _parse_csv(scanners_arg) if s in SUPPORTED_SCANNERS]
    if not scanners:
        raise SystemExit("No valid scanners specified for benchmark mode.")

    req = RunRequest(
        invocation_mode="benchmark",
        case=case,
        repo_id=repo_id,
        scanners=scanners,
        suite_root=suite_root,
        suite_id=suite_id,
        use_suite=not bool(args.no_bundle),
        dry_run=bool(args.dry_run),
        quiet=bool(args.quiet),
        skip_analysis=bool(args.skip_analysis),
        tolerance=int(args.tolerance),
        analysis_filter=str(args.analysis_filter),
        sonar_project_key=args.sonar_project_key,
        aikido_git_ref=args.aikido_git_ref,
        argv=list(sys.argv),
        python_executable=sys.executable,
    )
    return int(pipeline.run(req))
