#!/usr/bin/env python3
"""
tools/core.py

Shared scanner plumbing used by tools/scan_*.py scripts.

Canonical utilities:
- JSON IO
- Command execution (no shell=True)
- Repo acquisition (clone/reuse OR local path)
- Run directory creation (YYYYMMDD##)
- Git commit + author metadata
- Repo-relative path + line-content helpers
- Common mapping loaders (CWE -> OWASP)

Tool-specific parsing stays in each scan_*.py.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from tools.io import read_json, read_line_content, write_json


# Repo root = parent of tools/
ROOT_DIR = Path(__file__).resolve().parents[1]


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

    # If env is provided, merge it onto the current process environment.
    env2 = None
    if env is not None:
        env2 = os.environ.copy()
        env2.update(env)

    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        timeout=timeout_seconds if timeout_seconds and timeout_seconds > 0 else None,
        env=env2,
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


# -------------------------
# Repo helpers
# -------------------------

def _anchor_under_root(path: Path) -> Path:
    """Anchor a relative path under the project root."""
    return path if path.is_absolute() else (ROOT_DIR / path)


def get_repo_name(repo_url: str) -> str:
    """
    Turn a Git URL into a simple repo name.

    Examples:
      https://github.com/juice-shop/juice-shop.git -> "juice-shop"
      git@github.com:juice-shop/juice-shop.git    -> "juice-shop"
      https://api.github.com/repos/org/repo       -> "repo"
    """
    last = repo_url.rstrip("/").split("/")[-1]
    return last[:-4] if last.endswith(".git") else last


def clone_repo(repo_url: str, base: Path | str = Path("repos")) -> Path:
    """
    Clone the given repo URL into ROOT_DIR / base / <repo_name>.

    If the repo already exists locally, it is reused.
    """
    base_path = base if isinstance(base, Path) else Path(base)
    base_path = _anchor_under_root(base_path)
    base_path.mkdir(parents=True, exist_ok=True)

    name = get_repo_name(repo_url)
    path = base_path / name

    if path.exists():
        return path.resolve()

    print(f"📥 Cloning {name} from {repo_url} ...")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, str(path)],
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed with code {result.returncode}")

    return path.resolve()


def get_git_commit(repo_path: Path) -> Optional[str]:
    """
    Return the current commit SHA for the repo at repo_path.
    Returns None if repo_path is not a git repo or git is unavailable.
    """
    res = run_cmd(
        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
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
        ['git', '-C', str(repo_path), 'rev-parse', '--abbrev-ref', 'HEAD'],
        print_stderr=False,
        print_stdout=False,
    )
    b = (res.stdout or '').strip()
    if res.exit_code != 0 or not b or b == 'HEAD':
        return None
    return b


def get_commit_author_info(repo_path: Path, commit: str) -> Dict[str, Optional[str]]:
    """
    Return author name/email/date for the given commit SHA in the repo.
    Never raises; returns keys with None if unavailable.
    """
    res = run_cmd(
        ["git", "-C", str(repo_path), "show", "-s", "--format=%an%n%ae%n%aI", commit],
        print_stderr=False,
        print_stdout=False,
    )
    if res.exit_code != 0:
        return {"commit_author_name": None, "commit_author_email": None, "commit_date": None}

    lines = (res.stdout or "").splitlines()
    return {
        "commit_author_name": lines[0].strip() if len(lines) > 0 and lines[0].strip() else None,
        "commit_author_email": lines[1].strip() if len(lines) > 1 and lines[1].strip() else None,
        "commit_date": lines[2].strip() if len(lines) > 2 and lines[2].strip() else None,
    }


# -------------------------
# Run directory
# -------------------------

def create_run_dir(output_root: Path | str) -> tuple[str, Path]:
    """
    Create a dated run directory like YYYYMMDD01, YYYYMMDD02, ... under output_root.

    If output_root is relative (e.g. 'runs/semgrep'), it is anchored under ROOT_DIR.
    """
    root = output_root if isinstance(output_root, Path) else Path(output_root)
    root = _anchor_under_root(root)
    root.mkdir(parents=True, exist_ok=True)

    today = datetime.now().strftime("%Y%m%d")

    existing = [
        d.name for d in root.iterdir()
        if d.is_dir() and d.name.startswith(today)
    ]
    if not existing:
        idx = 1
    else:
        last = max(existing)
        try:
            last_idx = int(last[-2:])
        except ValueError:
            last_idx = len(existing)
        idx = last_idx + 1

    run_id = f"{today}{idx:02d}"
    run_dir = root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_id, run_dir


def create_run_dir_compat(output_root: Union[str, Path]) -> Tuple[str, Path]:
    """
    Backwards-compatible alias kept so scan scripts can keep calling create_run_dir_compat().
    """
    run_id, run_dir = create_run_dir(output_root)
    return run_id, run_dir


# -------------------------
# Repo acquisition + metadata
# -------------------------

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
    Else: clone/reuse repo_url under repos_dir.

    Returns TargetRepo(repo_path, repo_name, repo_url, commit).
    """
    if repo_path:
        p = Path(repo_path).resolve()
        return TargetRepo(
            repo_path=p,
            repo_name=p.name,
            repo_url=repo_url,
            commit=get_git_commit(p),
        )

    if not repo_url:
        raise ValueError("acquire_repo requires either repo_url or repo_path.")

    repos_base = repos_dir if isinstance(repos_dir, Path) else Path(repos_dir)
    repos_base = _anchor_under_root(repos_base)

    p = clone_repo(repo_url, base=repos_base)
    name = get_repo_name(repo_url) or p.name
    commit = get_git_commit(p)

    return TargetRepo(repo_path=p, repo_name=name, repo_url=repo_url, commit=commit)


def get_commit_author_info_compat(repo_path: Path, commit: Optional[str]) -> Dict[str, Optional[str]]:
    """
    Backwards-compatible helper.

    Returns keys with None if commit info isn't available; never raises.
    """
    base = {"commit_author_name": None, "commit_author_email": None, "commit_date": None}
    if not commit:
        return base
    try:
        base.update(get_commit_author_info(repo_path, commit))
    except Exception:
        # Swallow errors: metadata should not break scans.
        pass
    return base


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
        "repo_path": str(repo.repo_path),
        "repo_branch": get_git_branch(repo.repo_path),
        "repo_commit": repo.commit,
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "command": command_str,
        "scan_time_seconds": scan_time_seconds,
        "exit_code": exit_code,
        **author_info,
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


## NOTE:
## JSON + line-content helpers live in tools/io.py.
## tools/core.py re-exports them for convenience/backwards-compat.


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


# -------------------------
# Deterministic output helpers
# -------------------------

def finalize_normalized_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Make normalized findings deterministic.

    Normalizers are allowed to be "thin" and focused on parsing, but the
    benchmark pipeline benefits enormously from stable ordering so runs can be
    diffed meaningfully.

    This helper:
      - sorts set-like list fields (e.g., cwe_ids)
      - sorts OWASP block codes/categories
      - sorts the overall findings list by a stable key

    It mutates dictionaries in-place (for efficiency) and returns the sorted
    list.
    """

    def _safe_int(x: Any) -> int:
        try:
            if x is None:
                return -1
            return int(x)
        except Exception:
            return -1

    def _sort_list_field(f: Dict[str, Any], key: str) -> None:
        v = f.get(key)
        if isinstance(v, list):
            # Treat as set-like: sort for stability.
            f[key] = sorted([str(x) for x in v if x is not None])

    def _sort_owasp_block(f: Dict[str, Any], key: str) -> None:
        block = f.get(key)
        if not isinstance(block, dict):
            return
        codes = block.get("codes")
        cats = block.get("categories")
        if isinstance(codes, list):
            block["codes"] = sorted([str(x) for x in codes if x is not None])
        if isinstance(cats, list):
            block["categories"] = sorted([str(x) for x in cats if x is not None])

    cleaned: List[Dict[str, Any]] = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue

        _sort_list_field(f, "cwe_ids")

        # OWASP blocks (compat + explicit vendor/canonical views)
        for k in (
            "owasp_top_10_2017",
            "owasp_top_10_2021",
            "owasp_top_10_2017_vendor",
            "owasp_top_10_2017_canonical",
            "owasp_top_10_2021_vendor",
            "owasp_top_10_2021_canonical",
        ):
            _sort_owasp_block(f, k)

        cleaned.append(f)

    def _key(f: Dict[str, Any]) -> tuple:
        return (
            str(f.get("file_path") or ""),
            _safe_int(f.get("line_number")),
            _safe_int(f.get("end_line_number")),
            str(f.get("rule_id") or ""),
            str(f.get("title") or ""),
            str(f.get("finding_id") or ""),
        )

    cleaned.sort(key=_key)
    return cleaned
