# pipeline/core.py
"""Core orchestration helpers for the SAST benchmark pipeline.

This module builds stable, correct command lines for the scanner entrypoints
in ``tools/scan_*.py``.

Clean-architecture boundary
---------------------------
Scanner-specific *quirks* (required env vars, extra derived args, and how a
tool identifies its target) are declared in :mod:`pipeline.scanners`.

This module only contains the generic command-shaping rules required to invoke
those entrypoints consistently.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from pipeline.identifiers import (
    derive_sonar_project_key,
    repo_id_from_repo_url,
    sanitize_sonar_key_fragment,
)
from pipeline.scanners import (
    SCANNER_SCRIPTS,
    SCANNER_TARGET_MODES,
    SCANNER_TRACKS,
    SUPPORTED_SCANNERS,
)

__all__ = [
    "PYTHON",
    "ROOT_DIR",
    "TOOLS_DIR",
    "filter_scanners_for_track",
    "script_path",
    "build_scan_command",
    "derive_sonar_project_key",
    "repo_id_from_repo_url",
    "sanitize_sonar_key_fragment",
]


# Use the same interpreter that imports this module (CLI inherits it).
PYTHON: str = sys.executable or "python"

# Repo root (pipeline/ is a top-level package dir)
ROOT_DIR: Path = Path(__file__).resolve().parents[1]
TOOLS_DIR: Path = ROOT_DIR / "tools"

# Scanner metadata (supported scanners, runner scripts, and track capabilities) is
# centralized in :mod:`pipeline.scanners` to avoid drift across CLI/execution/analysis.


def filter_scanners_for_track(
    scanners: Sequence[str], track: str
) -> tuple[list[str], list[str]]:
    """Filter a scanner list to only those that support the given track.

    Returns (kept, skipped). Unknown tracks are treated as "no filter".
    """

    t = (track or "").strip().lower()
    if not t:
        return list(scanners), []

    # If the track isn't one we recognize, do not filter (best-effort).
    known_tracks = {x for s in SCANNER_TRACKS.values() for x in s}
    if t not in known_tracks:
        return list(scanners), []

    kept: list[str] = []
    skipped: list[str] = []
    for s in scanners:
        supported = SCANNER_TRACKS.get(str(s), {t})
        if t in supported:
            kept.append(str(s))
        else:
            skipped.append(str(s))

    return kept, skipped


def script_path(scanner: str) -> Path:
    """Return the tools/scan_*.py path for a scanner."""
    if scanner not in SUPPORTED_SCANNERS:
        raise ValueError(
            f"Unsupported scanner: {scanner!r}. Supported: {sorted(SUPPORTED_SCANNERS)}"
        )
    p = TOOLS_DIR / SCANNER_SCRIPTS[scanner]
    if not p.exists():
        raise FileNotFoundError(f"Scanner script not found: {p}")
    return p


def _render_extra_args(extra_args: Optional[Dict[str, Any]]) -> List[str]:
    """Convert an ``extra_args`` dict into CLI args.

    Rules:
    - key -> "--key"
    - value is True  => flag only: "--key"
    - value is False/None => omitted
    - value is list/tuple => repeated "--key value" pairs
    - otherwise => "--key str(value)"
    """
    if not extra_args:
        return []

    parts: List[str] = []
    for k, v in extra_args.items():
        if v is None or v is False:
            continue
        flag = f"--{k}"
        if v is True:
            parts.append(flag)
            continue
        if isinstance(v, (list, tuple)):
            for item in v:
                if item is None:
                    continue
                parts.extend([flag, str(item)])
            continue
        parts.extend([flag, str(v)])
    return parts


def build_scan_command(
    scanner: str,
    *,
    repo_url: Optional[str] = None,
    repo_path: Optional[Union[str, Path]] = None,
    extra_args: Optional[Dict[str, Any]] = None,
    python_executable: Optional[str] = None,
) -> List[str]:
    """Build a command list to run a scanner script.

    Parameters
    ----------
    scanner:
        One of: semgrep, sonar, snyk, aikido.
    repo_url:
        Git URL of the target (required for most scanners unless repo_path is used).
    repo_path:
        Local repo path (skips clone). If provided, will pass --repo-path.
    extra_args:
        Extra flags to pass to the scanner script. Keys must be in "kebab-case"
        matching the script's argparse options (e.g. {"project-key": "..."}).
    python_executable:
        Override python executable. Defaults to ``sys.executable``.
    """
    py = python_executable or PYTHON
    script = script_path(scanner)

    # Prefer module execution so imports behave consistently (cwd rooted at repo root).
    # This avoids relying on file paths like tools/scan_*.py.
    module = f"tools.{script.stem}"
    cmd: List[str] = [py, "-m", module]

    # ---- Non-standard target modes (declared by the registry) ----
    if SCANNER_TARGET_MODES.get(scanner) == "git-ref":
        # Some scanners (currently Aikido cloud mode) identify repos by a git
        # reference / slug, not a local path or repo URL.
        #
        # When scanning via --repo-path (e.g., suite worktrees/clones) we may not
        # have a repo_url available, so allow an explicit override via
        # extra_args["git-ref"].
        extra = dict(extra_args or {})
        override = extra.pop("git-ref", None)
        if override:
            git_ref = str(override).strip()
        elif repo_url:
            git_ref = repo_url.rstrip("/").replace(".git", "")
        else:
            raise ValueError(
                f"Scanner {scanner!r} requires repo_url or extra_args['git-ref'] to set --git-ref."
            )
        if not git_ref:
            raise ValueError("Empty git-ref (from repo_url or extra_args['git-ref']).")
        cmd += ["--git-ref", git_ref]
        cmd += _render_extra_args(extra)
        return cmd

    # ---- Standard repo args (most scanners) ----
    if repo_path:
        # NOTE: many scan_*.py entrypoints treat --repo-url and --repo-path as mutually exclusive.
        # When a local repo path is provided, pass only --repo-path to avoid argparse errors.
        cmd += ["--repo-path", str(Path(repo_path).resolve())]
    elif repo_url:
        cmd += ["--repo-url", repo_url]
    else:
        raise ValueError("Missing repo_url/repo_path (need one).")

    cmd += _render_extra_args(extra_args)
    return cmd


# NOTE: Sonar key helpers moved to :mod:`pipeline.identifiers`.
#
# They are imported above to keep backwards-compatible imports like:
#
#   from pipeline.core import sanitize_sonar_key_fragment
#
# but the implementation now lives in a dedicated pure module to avoid
# core<->scanners import-cycle pressure.
