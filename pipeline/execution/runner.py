"""pipeline.execution.runner

Subprocess execution helpers for :mod:`pipeline.execution.run_case`.

Rule
----
Only this module should touch ``subprocess``.
"""

from __future__ import annotations

import os
import subprocess
from typing import Optional

from pipeline.core import ROOT_DIR as REPO_ROOT

from .model import ToolExecution, ToolInvocation, now_iso


def run_invocation(inv: ToolInvocation, *, dry_run: bool, quiet: bool) -> ToolExecution:
    """Execute one tool invocation via subprocess."""

    print("  Command :", inv.command_str)
    if dry_run:
        print("  (dry-run: not executing)")
        t = now_iso()
        return ToolExecution(invocation=inv, exit_code=0, started=t, finished=t)

    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")

    started = now_iso()

    if quiet:
        result = subprocess.run(
            inv.cmd,
            env=env,
            cwd=str(REPO_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        result = subprocess.run(inv.cmd, env=env, cwd=str(REPO_ROOT))

    finished = now_iso()
    return ToolExecution(
        invocation=inv,
        exit_code=int(result.returncode),
        started=started,
        finished=finished,
    )


def detect_git_branch(repo_path: Optional[str]) -> Optional[str]:
    """Best-effort detect current git branch name for a local repo checkout."""

    if not repo_path:
        return None
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_path), "rev-parse", "--abbrev-ref", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=20,
        ).strip()
        if not out or out == "HEAD":
            return None
        return out
    except Exception:
        return None


def detect_git_commit(repo_path: Optional[str]) -> Optional[str]:
    """Best-effort detect current git commit SHA for a local repo checkout."""

    if not repo_path:
        return None
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=20,
        ).strip()
        return out or None
    except Exception:
        return None
