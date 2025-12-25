#!/usr/bin/env python3
"""
tools/core.py

Shared scanner plumbing used by tools/scan_*.py scripts.

This module is intentionally "boring" and stable:
- JSON IO
- command execution helpers (safe: no shell=True)
- repo acquisition (clone/reuse OR local path)
- run directory creation (compat with run_utils drift)
- metadata building (never fails scan if author info missing)
- repo-relative path + line-content helpers
- common mapping loaders (CWE -> OWASP)

Tool-specific parsing stays in each scan_*.py.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# Repo root = parent of tools/
ROOT_DIR = Path(__file__).resolve().parents[1]


# -------------------------
# JSON IO
# -------------------------

def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


# -------------------------
# Command helpers
# -------------------------

@dataclass(frozen=True)
class CmdResult:
    exit_code: int
    elapsed_seconds: float
    command_str: str
    stdout: str
    stderr: str


def which_or_raise(bin_name: str, fallbacks: Optional[List[str]] = None) -> str:
    """
    Locate an executable. Returns absolute path.

    Why this exists:
    - prevents "FileNotFoundError: snyk/semgrep not found"
    - avoids PATH surprises across conda/CI/brew/pipx
    """
    found = shutil.which(bin_name)
    if found:
        return found

    for candidate in (fallbacks or []):
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
    """
    Run a subprocess and capture stdout/stderr. Does NOT use shell=True.

    Never raises on non-zero exit codes; only raises on execution errors
    (e.g. binary not found).
    """
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            text=True,
            capture_output=True,
            timeout=timeout_seconds if timeout_seconds and timeout_seconds > 0 else None,
            env=env,
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
    except subprocess.TimeoutExpired as e:
        elapsed = time.time() - t0
        return CmdResult(
            exit_code=124,
            elapsed_seconds=elapsed,
            command_str=" ".join(cmd),
            stdout=e.stdout or "",
            stderr=e.stderr or "",
        )


# -------------------------
# run_utils import + compat
# -------------------------

def _import_run_utils():
    """
    Import run_utils with a tolerant fallback, since scan scripts run as scripts.
    """
    try:
        import run_utils  # type: ignore
        return run_utils
    except Exception:
        from tools import run_utils  # type: ignore
        return run_utils


@dataclass(frozen=True)
class TargetRepo:
    repo_path: Path
    repo_name: str
    repo_url: Optional[str]
    commit: Optional[str]


def acquire_repo(
    *,
    repo_url: Optional[str],
    repo_path: Optional[str],
    repos_dir: Union[str, Path] = "repos",
) -> TargetRepo:
    """
    Standard repo acquisition for all scanners.

    If repo_path is provided: use it, do not clone.
    Else: clone/reuse repo_url under repos_dir using run_utils.clone_repo.

    Returns TargetRepo(repo_path, repo_name, repo_url, commit).
    """
    ru = _import_run_utils()

    if repo_path:
        p = Path(repo_path).resolve()
        name = p.name
        commit = None
        if hasattr(ru, "get_git_commit"):
            try:
                commit = ru.get_git_commit(p)  # type: ignore
            except Exception:
                commit = None
        return TargetRepo(repo_path=p, repo_name=name, repo_url=repo_url, commit=commit)

    if not repo_url:
        raise ValueError("acquire_repo requires either repo_url or repo_path.")

    repos_base = Path(repos_dir).resolve()
    repos_base.mkdir(parents=True, exist_ok=True)

    # clone_repo signature drift: support clone_repo(url, base) and clone_repo(url, base=...)
    try:
        p = ru.clone_repo(repo_url, repos_base)  # type: ignore
    except TypeError:
        p = ru.clone_repo(repo_url, base=repos_base)  # type: ignore

    p = p if isinstance(p, Path) else Path(p).resolve()

    # repo_name
    if hasattr(ru, "get_repo_name"):
        try:
            name = ru.get_repo_name(repo_url)  # type: ignore
        except Exception:
            name = p.name
    else:
        name = p.name

    # commit
    commit = None
    if hasattr(ru, "get_git_commit"):
        try:
            commit = ru.get_git_commit(p)  # type: ignore
        except Exception:
            commit = None

    return TargetRepo(repo_path=p, repo_name=name, repo_url=repo_url, commit=commit)


def create_run_dir_compat(output_root: Union[str, Path]) -> Tuple[str, Path]:
    """
    Wrap run_utils.create_run_dir() to adapt to signature/return shape drift.

    Input:
      output_root = runs/<scanner>/<repo_name>

    Returns:
      (run_id, run_dir)
    """
    ru = _import_run_utils()
    out = Path(output_root).resolve()
    out.mkdir(parents=True, exist_ok=True)

    if hasattr(ru, "create_run_dir"):
        res = ru.create_run_dir(out)  # type: ignore

        # Shapes seen:
        #  - (run_id, run_dir)
        #  - (run_dir, run_id)
        #  - run_dir only
        if isinstance(res, tuple) and len(res) == 2:
            a, b = res
            if isinstance(a, str) and isinstance(b, (str, Path)):
                return a, Path(b)
            if isinstance(a, Path) and isinstance(b, str):
                return b, a
            if isinstance(a, Path) and isinstance(b, Path):
                return b.name, b
            if isinstance(a, str) and isinstance(b, str):
                return a, Path(b)

        if isinstance(res, Path):
            return res.name, res

        if isinstance(res, str):
            p = Path(res)
            return p.name, p

    # fallback: timestamp run id
    run_id = datetime.now().strftime("%Y%m%d%H")
    run_dir = out / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_id, run_dir


def get_commit_author_info_compat(repo_path: Path, commit: Optional[str]) -> Dict[str, Any]:
    """
    Your run_utils.get_commit_author_info typically wants (repo_path, commit).
    This wrapper never fails scans if metadata is unavailable.
    """
    if not commit:
        return {}

    ru = _import_run_utils()
    if not hasattr(ru, "get_commit_author_info"):
        return {}

    try:
        return ru.get_commit_author_info(repo_path, commit) or {}  # type: ignore
    except TypeError:
        # if signature changes in the future, try best-effort fallback
        try:
            return ru.get_commit_author_info(repo_path) or {}  # type: ignore
        except Exception:
            return {}
    except Exception:
        return {}


def build_run_metadata(
    *,
    scanner: str,
    scanner_version: str,
    repo: TargetRepo,
    run_id: str,
    command_str: str,
    scan_time_seconds: float,
    exit_code: int,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Standard metadata dict written by all scanners.
    """
    author_info = get_commit_author_info_compat(repo.repo_path, repo.commit)

    data: Dict[str, Any] = {
        "scanner": scanner,
        "scanner_version": scanner_version,
        "repo_name": repo.repo_name,
        "repo_url": repo.repo_url,
        "repo_commit": repo.commit,
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "command": command_str,
        "scan_time_seconds": scan_time_seconds,
        "exit_code": exit_code,
        **(author_info or {}),
    }
    if extra:
        data.update(extra)
    return data


# -------------------------
# Source location helpers
# -------------------------

def normalize_repo_relative_path(repo_path: Path, tool_path: Optional[str]) -> Optional[str]:
    """
    Convert tool-reported absolute paths to repo-relative if possible.
    """
    if not tool_path:
        return None
    p = Path(tool_path)
    try:
        if p.is_absolute():
            return str(p.resolve().relative_to(repo_path.resolve()))
    except Exception:
        return tool_path
    return tool_path


def read_line_content(repo_path: Path, file_path: Optional[str], line_no: Optional[int]) -> Optional[str]:
    """
    Read a specific 1-indexed line from repo_path/file_path.
    """
    if not file_path or not line_no:
        return None
    try:
        abs_path = (repo_path / file_path).resolve()
        if not abs_path.exists():
            return None
        with abs_path.open("r", encoding="utf-8", errors="replace") as f:
            for i, ln in enumerate(f, start=1):
                if i == int(line_no):
                    return ln.rstrip("\n")
    except Exception:
        return None
    return None


# -------------------------
# Shared mapping loaders
# -------------------------

def load_cwe_to_owasp_map(mappings_dir: Optional[Path] = None) -> Dict[str, Any]:
    """
    Load mappings/cwe_to_owasp_top10_mitre.json.
    Return dict (possibly empty). Resolver supports different shapes.
    """
    mappings_dir = mappings_dir or (ROOT_DIR / "mappings")
    p = mappings_dir / "cwe_to_owasp_top10_mitre.json"
    if not p.exists():
        return {}
    try:
        data = read_json(p)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}
