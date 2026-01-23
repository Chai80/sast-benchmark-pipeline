"""cli.commands.suite.runbook_steps.summary

Small UX helpers for the suite runbook.
"""

from __future__ import annotations

from .model import SuiteRunContext


def print_suite_complete(ctx: SuiteRunContext) -> None:
    """Print a compact end-of-run summary."""

    print("\n✅ Suite complete")
    print(f"  Suite id : {ctx.suite_id}")
    print(f"  Suite dir: {ctx.suite_dir}")
