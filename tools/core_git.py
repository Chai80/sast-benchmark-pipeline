"""tools/core_git.py

Git metadata helpers.

These are used in two contexts:

1) For the *pipeline repo itself* (best-effort provenance), via
   :func:`get_pipeline_git_commit`.
2) For scanned repos, via :func:`get_git_commit`, :func:`get_git_branch`, and
   :func:`get_commit_author_info`.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, Optional

from .core_cmd import run_cmd
from .core_root import ROOT_DIR


_PIPELINE_GIT_COMMIT: Optional[str] = None


def get_pipeline_git_commit() -> Optional[str]:
    """Best-effort commit hash for *this* pipeline repo (not the scanned repo)."""
    global _PIPELINE_GIT_COMMIT
    if _PIPELINE_GIT_COMMIT is not None:
        return _PIPELINE_GIT_COMMIT
    try:
        out = subprocess.check_output(
            ["git", "-C", str(ROOT_DIR), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        _PIPELINE_GIT_COMMIT = out or None
    except Exception:
        _PIPELINE_GIT_COMMIT = None
    return _PIPELINE_GIT_COMMIT


def get_git_commit(repo_path: Path) -> Optional[str]:
    """Return the current commit SHA for the repo at repo_path.

    Returns None if repo_path is not a git repo or git is unavailable.
    """
    res = run_cmd(
        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
        timeout_seconds=20,
        print_stderr=False,
        print_stdout=False,
    )
    sha = (res.stdout or "").strip()
    return sha if res.exit_code == 0 and sha else None


def get_git_branch(repo_path: Path) -> Optional[str]:
    """Return the current branch name for the repo at repo_path.

    Returns None if the repo is detached (HEAD) or git is unavailable.
    """
    res = run_cmd(
        ["git", "-C", str(repo_path), "rev-parse", "--abbrev-ref", "HEAD"],
        timeout_seconds=20,
        print_stderr=False,
        print_stdout=False,
    )
    b = (res.stdout or "").strip()
    if res.exit_code != 0 or not b or b == "HEAD":
        return None
    return b


def get_commit_author_info(repo_path: Path, commit: str) -> Dict[str, Optional[str]]:
    """Return author name/email/date for the given commit SHA in the repo.

    Never raises; returns keys with None if unavailable.
    """
    res = run_cmd(
        ["git", "-C", str(repo_path), "show", "-s", "--format=%an%n%ae%n%aI", commit],
        timeout_seconds=20,
        print_stderr=False,
        print_stdout=False,
    )
    if res.exit_code != 0:
        return {
            "commit_author_name": None,
            "commit_author_email": None,
            "commit_date": None,
        }

    lines = (res.stdout or "").splitlines()
    return {
        "commit_author_name": lines[0].strip() if len(lines) > 0 and lines[0].strip() else None,
        "commit_author_email": lines[1].strip() if len(lines) > 1 and lines[1].strip() else None,
        "commit_date": lines[2].strip() if len(lines) > 2 and lines[2].strip() else None,
    }
