"""tools/core_cmd.py

Command-execution helpers shared across scanner adapters.

This module deliberately avoids tool-specific knowledge. It provides:

* :func:`which_or_raise` - resolve executables reliably across environments.
* :func:`run_cmd` - run subprocesses (no shell=True) and capture output.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass(frozen=True)
class CmdResult:
    exit_code: int
    elapsed_seconds: float
    command_str: str
    stdout: str
    stderr: str


def which_or_raise(bin_name: str, fallbacks: Optional[List[str]] = None) -> str:
    """Locate an executable and return its absolute path.

    Why this exists:
    - prevents "FileNotFoundError: snyk/semgrep not found"
    - avoids PATH surprises across conda/CI/brew/pipx
    """
    found = shutil.which(bin_name)
    if found:
        return found

    for candidate in fallbacks or []:
        p = Path(candidate)
        if p.exists() and os.access(str(p), os.X_OK):
            return str(p)

    raise FileNotFoundError(
        f"Executable '{bin_name}' not found on PATH.\n"
        f"Install it and ensure it's available to this Python process.\n"
        f"Tried fallbacks: {fallbacks or []}"
    )


def run_cmd(
    cmd: List[str],
    *,
    cwd: Optional[Path] = None,
    timeout_seconds: int = 0,
    env: Optional[Dict[str, str]] = None,
    print_stderr: bool = True,
    print_stdout: bool = False,
) -> CmdResult:
    """Run a subprocess and capture stdout/stderr (no ``shell=True``).

    Never raises on non-zero exit codes; only raises on execution errors
    (e.g. binary not found).
    """
    t0 = time.time()

    # If env is provided, merge it onto the current process environment.
    env2 = None
    if env is not None:
        env2 = os.environ.copy()
        env2.update(env)

    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        timeout=timeout_seconds if timeout_seconds and timeout_seconds > 0 else None,
        env=env2,
    )
    elapsed = time.time() - t0

    # Many tools write progress to stderr even on success.
    if print_stderr and proc.stderr:
        print(proc.stderr, file=sys.stderr)
    if print_stdout and proc.stdout:
        print(proc.stdout)

    return CmdResult(
        exit_code=proc.returncode,
        elapsed_seconds=elapsed,
        command_str=" ".join(cmd),
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
    )
