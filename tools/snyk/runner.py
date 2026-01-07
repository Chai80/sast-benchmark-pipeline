"""tools/snyk/runner.py

Tool-specific execution plumbing for Snyk Code (SARIF).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from tools.core import create_run_dir_compat, run_cmd

SNYK_BIN_FALLBACKS = ["/opt/homebrew/bin/snyk", "/usr/local/bin/snyk"]


@dataclass(frozen=True)
class RunPaths:
    run_dir: Path
    raw_sarif: Path
    normalized: Path
    metadata: Path


def prepare_run_paths(output_root: str, repo_name: str) -> Tuple[str, RunPaths]:
    """Prepare per-run output paths.

    Layouts supported:
    - v2 (suite/case): <output_root>/<run_id>/{raw.sarif,normalized.json,metadata.json}
      where output_root is cases/<case>/tool_runs/<tool>
    - v1 (legacy):     <output_root>/<repo_name>/<run_id>/{<repo>.sarif,<repo>.normalized.json,metadata.json}
    """
    out_root = Path(output_root)
    suite_mode = out_root.parent.name in {"tool_runs", "scans"}

    if suite_mode:
        run_id, run_dir = create_run_dir_compat(out_root)
        raw = run_dir / "raw.sarif"
        norm = run_dir / "normalized.json"
    else:
        run_id, run_dir = create_run_dir_compat(out_root / repo_name)
        raw = run_dir / f"{repo_name}.sarif"
        norm = run_dir / f"{repo_name}.normalized.json"

    return run_id, RunPaths(
        run_dir=run_dir,
        raw_sarif=raw,
        normalized=norm,
        metadata=run_dir / "metadata.json",
    )


def require_snyk_token() -> None:
    if not os.environ.get("SNYK_TOKEN"):
        raise SystemExit(
            "Missing SNYK_TOKEN environment variable.\n"
            "Set it in your shell or .env before running."
        )


def snyk_version(snyk_bin: str) -> str:
    res = run_cmd([snyk_bin, "--version"], print_stderr=False, print_stdout=False)
    return (res.stdout or res.stderr).strip() or "unknown"


def run_snyk_code_sarif(*, snyk_bin: str, repo_path: Path, out_sarif: Path) -> Tuple[int, float, str]:
    """Run: snyk code test --sarif --sarif-file-output <out_sarif>"""
    require_snyk_token()
    cmd = [
        snyk_bin,
        "code",
        "test",
        "--sarif",
        "--sarif-file-output",
        str(out_sarif),
    ]
    verbose = os.environ.get("SAST_VERBOSE", "").strip().lower() in {"1", "true", "yes", "y"}
    res = run_cmd(cmd, cwd=repo_path, print_stderr=True, print_stdout=verbose)
    return res.exit_code, res.elapsed_seconds, res.command_str
