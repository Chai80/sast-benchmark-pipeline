"""tools/snyk/runner.py

Tool-specific execution plumbing for Snyk Code (SARIF).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple

from sast_benchmark.io.layout import RunPaths, prepare_run_paths as _prepare_run_paths
from tools.core import run_cmd

SNYK_BIN_FALLBACKS = ["/opt/homebrew/bin/snyk", "/usr/local/bin/snyk"]


def prepare_run_paths(output_root: str, repo_name: str) -> Tuple[str, RunPaths]:
    """Prepare per-run output paths.

    Delegates to :func:`sast_benchmark.io.layout.prepare_run_paths` so the
    filesystem contract is owned by one module.
    """
    return _prepare_run_paths(output_root, repo_name, raw_extension=".sarif")


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
