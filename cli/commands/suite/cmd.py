from __future__ import annotations

import argparse
from typing import Dict

from pipeline.pipeline import SASTBenchmarkPipeline

from .runbook import run_suite_runbook


def run_suite_mode(
    args: argparse.Namespace,
    pipeline: SASTBenchmarkPipeline,
    *,
    repo_registry: Dict[str, Dict[str, str]],
) -> int:
    """Run multiple cases under one suite id.

    Suite definitions are Python-only at runtime:
    - If --suite-file is provided, it must be a .py file exporting SUITE_DEF.
    - Otherwise we prompt interactively.
    """

    return run_suite_runbook(args, pipeline, repo_registry=repo_registry)
