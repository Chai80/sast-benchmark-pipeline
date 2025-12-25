# pipeline/core.py
from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Optional

PYTHON = sys.executable or "python"

ROOT_DIR = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT_DIR / "tools"

SUPPORTED_SCANNERS = {"semgrep", "snyk", "sonar", "aikido"}


def _script_for(scanner: str) -> Path:
    if scanner not in SUPPORTED_SCANNERS:
        raise ValueError(f"Unknown scanner '{scanner}'. Valid: {sorted(SUPPORTED_SCANNERS)}")
    script = TOOLS_DIR / f"scan_{scanner}.py"
    if not script.exists():
        raise FileNotFoundError(f"Scanner script not found: {script}")
    return script


def build_scan_command(
    scanner: str,
    *,
    repo_url: Optional[str] = None,
    repo_path: Optional[str] = None,
    extra_args: Optional[Dict[str, str]] = None,
) -> List[str]:
    """
    Build subprocess command to run tools/scan_<scanner>.py.

    This is intentionally benchmark-free:
    - caller provides repo_url or repo_path
    - command is returned as a list (safe, no shell)
    """
    script = _script_for(scanner)

    cmd: List[str] = [PYTHON, str(script)]

    if repo_path:
        cmd += ["--repo-path", repo_path]
        # Optional: some scanners may store repo_url in metadata if provided
        if repo_url:
            cmd += ["--repo-url", repo_url]
    else:
        if not repo_url:
            raise ValueError("You must provide repo_url or repo_path.")
        cmd += ["--repo-url", repo_url]

    if extra_args:
        for k, v in extra_args.items():
            if not k.startswith("--"):
                k = "--" + k
            cmd += [k, str(v)]

    return cmd


# -------------------------------------------------------------------
# Backwards-compatible API (so older code doesn't break)
# -------------------------------------------------------------------

def build_command(scanner: str, target: str | dict) -> List[str]:
    """
    Legacy function name used by older code.

    Previously, 'target' was a benchmark key or a target dict.
    We no longer depend on benchmarks; so we support:
      - target is dict with repo_url / repo_path
      - target is string treated as repo_url (if it looks like URL) or repo_path otherwise
    """
    repo_url: Optional[str] = None
    repo_path: Optional[str] = None

    if isinstance(target, dict):
        repo_url = target.get("repo_url") or target.get("url")
        repo_path = target.get("repo_path") or target.get("path")
    else:
        t = str(target).strip()
        if t.startswith(("http://", "https://", "git@")):
            repo_url = t
        else:
            repo_path = t

    return build_scan_command(scanner, repo_url=repo_url, repo_path=repo_path)


def build_scan_command_for_target(scanner: str, target_key: str) -> List[str]:
    """
    Deprecated: benchmarks are removed.
    Keep this only if something still calls it; otherwise delete it later.
    """
    raise RuntimeError(
        "build_scan_command_for_target() is no longer supported because benchmarks were removed. "
        "Pass repo_url or repo_path directly to build_scan_command()."
    )
