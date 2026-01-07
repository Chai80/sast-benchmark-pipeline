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
    """Prepare per-run output paths.

    Layouts supported:
    - v2 (suite/case): <output_root>/<run_id>/{raw.json,normalized.json,metadata.json}
      where output_root is cases/<case>/tool_runs/<tool>
    - v1 (legacy):     <output_root>/<repo_name>/<run_id>/{<repo>.json,<repo>.normalized.json,metadata.json}
    """
    out_root = Path(output_root)

    # In suite mode, sast_cli passes .../cases/<case>/(tool_runs|scans)/<tool>
    # and we flatten away the redundant repo_name directory.
    suite_mode = out_root.parent.name in {"tool_runs", "scans"}

    if suite_mode:
        run_id, run_dir = create_run_dir_compat(out_root)
        raw = run_dir / "raw.json"
        norm = run_dir / "normalized.json"
    else:
        run_id, run_dir = create_run_dir_compat(out_root / repo_name)
        raw = run_dir / f"{repo_name}.json"
        norm = run_dir / f"{repo_name}.normalized.json"

    return run_id, RunPaths(
        run_dir=run_dir,
        raw_results=raw,
        normalized=norm,
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
