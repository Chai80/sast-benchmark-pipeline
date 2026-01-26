"""tools/semgrep/runner.py

Tool-specific execution plumbing for Semgrep.
Keeps Semgrep CLI quirks and run-directory layout close to the tool.
"""

from __future__ import annotations

from pathlib import Path
from typing import Tuple

from sast_benchmark.io.layout import RunPaths, prepare_run_paths as _prepare_run_paths
from tools.core import run_cmd

SEMGREP_FALLBACKS = ["/opt/homebrew/bin/semgrep", "/usr/local/bin/semgrep"]

# Avoid walking large tool-generated scratch directories when scanning shared worktrees.
DEFAULT_EXCLUDES = [".scannerwork"]


def prepare_run_paths(output_root: str, repo_name: str) -> Tuple[str, RunPaths]:
    """Prepare per-run output paths.

    Delegates to :func:`sast_benchmark.io.layout.prepare_run_paths` so the
    filesystem contract is owned by one module.
    """
    return _prepare_run_paths(output_root, repo_name, raw_extension=".json")


def semgrep_version(semgrep_bin: str) -> str:
    res = run_cmd([semgrep_bin, "--version"], print_stderr=False, print_stdout=False)
    return (res.stdout or res.stderr).strip() or "unknown"


def run_semgrep(
    *,
    semgrep_bin: str,
    repo_path: Path,
    config: str,
    output_path: Path,
    timeout_seconds: int = 0,
) -> Tuple[int, float, str]:
    cmd = [
        semgrep_bin,
        "--json",
        *[arg for pat in DEFAULT_EXCLUDES for arg in ("--exclude", pat)],
        "--config",
        config,
        "--output",
        str(output_path),
    ]
    res = run_cmd(
        cmd,
        cwd=repo_path,
        timeout_seconds=timeout_seconds,
        print_stderr=True,
        print_stdout=False,
    )
    return res.exit_code, res.elapsed_seconds, res.command_str
