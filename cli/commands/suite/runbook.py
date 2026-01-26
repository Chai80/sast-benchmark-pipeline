"""cli.commands.suite.runbook

Suite-mode CLI runbook.

This module reads top-to-bottom as a coordinator. The implementation details
for each step live in :mod:`cli.commands.suite.runbook_steps`.

Backwards compatibility
-----------------------
Historically, :mod:`cli.commands.suite.cmd` imported many helper functions from
this module. We keep those names here by re-exporting the new step functions.
"""

from __future__ import annotations

import argparse
from typing import Dict

from pipeline.pipeline import SASTBenchmarkPipeline

from .runbook_steps.model import (
    GTToleranceSweepState,
    ROOT_DIR,
    SuiteFlags,
    SuiteRunContext,
)
from .runbook_steps.execute import run_suite_cases
from .runbook_steps.qa import build_suite_artifacts, post_run_aggregation_and_qa
from .runbook_steps.resolve import (
    apply_qa_case_selection,
    load_or_build_suite_def,
    maybe_bootstrap_worktrees,
    maybe_write_replay_file,
    resolve_suite_run_and_dirs,
    validate_suite_args,
)
from .runbook_steps.summary import print_suite_complete


def run_suite_runbook(
    args: argparse.Namespace,
    pipeline: SASTBenchmarkPipeline,
    *,
    repo_registry: Dict[str, Dict[str, str]],
) -> int:
    """Run multiple cases under one suite id (suite mode).

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

    print_suite_complete(ctx)
    return int(overall)


__all__ = [
    # Coordinator
    "run_suite_runbook",
    # Models
    "ROOT_DIR",
    "SuiteRunContext",
    "SuiteFlags",
    "GTToleranceSweepState",
    # Steps
    "validate_suite_args",
    "maybe_bootstrap_worktrees",
    "load_or_build_suite_def",
    "apply_qa_case_selection",
    "resolve_suite_run_and_dirs",
    "maybe_write_replay_file",
    "run_suite_cases",
    "build_suite_artifacts",
    "post_run_aggregation_and_qa",
    "print_suite_complete",
]
