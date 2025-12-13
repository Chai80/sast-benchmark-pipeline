# pipeline/core.py
from __future__ import annotations

import sys
from pathlib import Path

from benchmarks.targets import BENCHMARKS

# Use same interpreter as caller (CLI or benchmark runner)
PYTHON = sys.executable or "python"

# Project root = one level up from pipeline/
ROOT_DIR = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT_DIR / "tools"

SUPPORTED_SCANNERS = {"semgrep", "snyk", "sonar", "aikido"}


def build_command(scanner: str, target_key: str) -> list[str]:
    """
    Given a scanner name and a benchmark key, return the command list
    we should run, e.g.:
        ['python', 'tools/scan_snyk.py', '--repo-url', 'https://...']
    """
    if scanner not in SUPPORTED_SCANNERS:
        raise ValueError(f"Unknown scanner '{scanner}'. Valid: {sorted(SUPPORTED_SCANNERS)}")

    if target_key not in BENCHMARKS:
        raise ValueError(f"Unknown target '{target_key}'. Valid: {sorted(BENCHMARKS.keys())}")

    target = BENCHMARKS[target_key]

    if scanner == "semgrep":
        return [
            PYTHON,
            str(TOOLS_DIR / "scan_semgrep.py"),
            "--repo-url",
            target["repo_url"],
        ]

    if scanner == "snyk":
        return [
            PYTHON,
            str(TOOLS_DIR / "scan_snyk.py"),
            "--repo-url",
            target["repo_url"],
        ]

    if scanner == "sonar":
        cmd = [
            PYTHON,
            str(TOOLS_DIR / "scan_sonar.py"),
            "--repo-url",
            target["repo_url"],
        ]
        # If we have a known project key, pass it
        if target.get("sonar_project_key"):
            cmd.extend(["--project-key", target["sonar_project_key"]])
        return cmd

    if scanner == "aikido":
        # Aikido uses --git-ref instead of --repo-url
        return [
            PYTHON,
            str(TOOLS_DIR / "scan_aikido.py"),
            "--git-ref",
            target["aikido_ref"],
        ]

    # Defensive fallback
    raise ValueError(f"Unhandled scanner '{scanner}'")
