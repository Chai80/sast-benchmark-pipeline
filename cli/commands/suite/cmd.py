from __future__ import annotations

import argparse
from typing import Dict

from pipeline.pipeline import SASTBenchmarkPipeline

from .runbook import (
    SuiteRunContext,
    apply_qa_case_selection,
    load_or_build_suite_def,
    maybe_bootstrap_worktrees,
    maybe_write_replay_file,
    post_run_aggregation_and_qa,
    resolve_suite_run_and_dirs,
    run_suite_cases,
    validate_suite_args,
)


def run_suite_mode(args: argparse.Namespace, pipeline: SASTBenchmarkPipeline, *, repo_registry: Dict[str, Dict[str, str]]) -> int:
    """Run multiple cases under one suite id.

    Suite definitions are Python-only at runtime:
    - If --suite-file is provided, it must be a .py file exporting SUITE_DEF.
    - Otherwise we prompt interactively.
    """

    if args.no_suite:
        print("❌ Suite mode requires suite layout (do not use --no-suite).")
        return 2

    ctx = SuiteRunContext.from_args(args=args, pipeline=pipeline, repo_registry=repo_registry)

    early_exit = validate_suite_args(ctx)
    if early_exit is not None:
        return int(early_exit)

    maybe_bootstrap_worktrees(ctx)

    suite_def = load_or_build_suite_def(ctx)

    suite_def, early_exit = apply_qa_case_selection(ctx, suite_def)
    if early_exit is not None:
        return int(early_exit)

    resolved_run, early_exit = resolve_suite_run_and_dirs(ctx, suite_def)
    if early_exit is not None:
        return int(early_exit)
    assert resolved_run is not None

    maybe_write_replay_file(ctx, resolved_run)

    overall = run_suite_cases(ctx, resolved_run)
    overall = post_run_aggregation_and_qa(ctx, resolved_run, overall)

    print("\n✅ Suite complete")
    print(f"  Suite id : {ctx.suite_id}")
    print(f"  Suite dir: {ctx.suite_dir}")
    return int(overall)
