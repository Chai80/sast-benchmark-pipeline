from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from cli.ui import choose_from_menu
from pipeline.models import CaseSpec
from pipeline.orchestrator import RunRequest
from pipeline.pipeline import SASTBenchmarkPipeline
from pipeline.scanners import SCANNER_LABELS, SUPPORTED_SCANNERS


def run_scan(
    args,
    pipeline: SASTBenchmarkPipeline,
    *,
    case: CaseSpec,
    repo_id: str,
    suite_root: Path,
    suite_id: Optional[str],
) -> int:
    scanner = args.scanner
    if scanner is None:
        scanner = choose_from_menu(
            "Choose a scanner:",
            {k: SCANNER_LABELS.get(k, k) for k in sorted(SUPPORTED_SCANNERS)},
        )

    req = RunRequest(
        invocation_mode="scan",
        case=case,
        repo_id=repo_id,
        scanners=[scanner],
        suite_root=suite_root,
        suite_id=suite_id,
        use_suite=not bool(args.no_suite),
        dry_run=bool(args.dry_run),
        quiet=bool(args.quiet),
        # scan mode never runs analysis
        skip_analysis=True,
        tolerance=int(args.tolerance),
        analysis_filter=str(args.analysis_filter),
        sonar_project_key=args.sonar_project_key,
        aikido_git_ref=args.aikido_git_ref,
        argv=list(sys.argv),
        python_executable=sys.executable,
    )
    return int(pipeline.run(req))
