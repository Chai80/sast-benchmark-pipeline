"""tools/semgrep/runner.py

Tool-specific execution plumbing for Semgrep.
Keeps Semgrep CLI quirks and run-directory layout close to the tool.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from tools.core import create_run_dir_compat, run_cmd

SEMGREP_FALLBACKS = ["/opt/homebrew/bin/semgrep", "/usr/local/bin/semgrep"]


@dataclass(frozen=True)
class RunPaths:
    run_dir: Path
    raw_results: Path
    normalized: Path
    metadata: Path


def prepare_run_paths(output_root: str, repo_name: str) -> Tuple[str, RunPaths]:
    run_id, run_dir = create_run_dir_compat(Path(output_root) / repo_name)
    return run_id, RunPaths(
        run_dir=run_dir,
        raw_results=run_dir / f"{repo_name}.json",
        normalized=run_dir / f"{repo_name}.normalized.json",
        metadata=run_dir / "metadata.json",
    )


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
        "--config",
        config,
        "--output",
        str(output_path),
    ]
    res = run_cmd(cmd, cwd=repo_path, timeout_seconds=timeout_seconds, print_stderr=True, print_stdout=False)
    return res.exit_code, res.elapsed_seconds, res.command_str
