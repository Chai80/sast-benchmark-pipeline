"""cli.commands.suite.runbook_steps.execute

Execution step: run every resolved case through the pipeline.
"""

from __future__ import annotations

import sys

from pipeline.orchestrator import RunRequest
from pipeline.suites.bundles import safe_name
from pipeline.suites.suite_resolver import ResolvedSuiteRun

from .model import SuiteRunContext


def run_suite_cases(ctx: SuiteRunContext, resolved_run: ResolvedSuiteRun) -> int:
    """Execute all resolved suite cases through the pipeline."""

    args = ctx.args
    suite_id = resolved_run.suite_id
    suite_root = resolved_run.suite_root

    scanners = list(ctx.scanners)
    tolerance = int(ctx.tolerance or 0)
    analysis_filter = str(ctx.analysis_filter or "")
    skip_analysis = bool(ctx.skip_analysis)

    print("\n🚀 Running suite")
    print(f"  Suite id : {suite_id}")
    print(f"  Suite dir: {resolved_run.suite_dir}")
    print(f"  Cases    : {len(resolved_run.cases)}")
    print(f"  Scanners : {', '.join(scanners)}")

    overall = 0
    for idx, rc in enumerate(resolved_run.cases, start=1):
        sc = rc.suite_case
        repo_id = rc.repo_id
        case = sc.case
        print("\n" + "=" * 72)
        print(f"🧪 Case {idx}/{len(resolved_run.cases)}: {case.case_id} ({case.label})")
        if case.repo.repo_url:
            print(f"  Repo URL : {case.repo.repo_url}")
        if case.repo.repo_path:
            print(f"  Repo path: {case.repo.repo_path}")

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
            skip_analysis=bool(skip_analysis),
            tolerance=int(tolerance),
            gt_tolerance=int(getattr(args, "gt_tolerance", 0)),
            gt_source=str(getattr(args, "gt_source", "auto")),
            analysis_filter=str(analysis_filter),
            exclude_prefixes=getattr(args, "exclude_prefixes", ()) or (),
            include_harness=bool(getattr(args, "include_harness", False)),
            sonar_project_key=sc.overrides.sonar_project_key or args.sonar_project_key,
            aikido_git_ref=sc.overrides.aikido_git_ref or args.aikido_git_ref,
            argv=list(sys.argv),
            python_executable=sys.executable,
        )

        rc_code = int(ctx.pipeline.run(req))
        overall = max(overall, rc_code)

    return overall
