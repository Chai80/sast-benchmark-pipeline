"""tools/core_repo.py

Repository acquisition helpers.

Scanner adapters need a consistent way to acquire a repo to scan:

* If the user provides a local path -> use it.
* Else, clone (or reuse) a repo URL under a shared repos/ directory.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from .core_git import get_git_commit
from .core_root import ROOT_DIR


def _anchor_under_root(path: Path) -> Path:
    """Anchor a relative path under the project root."""
    return path if path.is_absolute() else (ROOT_DIR / path)


def get_repo_name(repo_url: str) -> str:
    """Turn a Git URL into a simple repo name.

    Examples:
      https://github.com/juice-shop/juice-shop.git -> "juice-shop"
      git@github.com:juice-shop/juice-shop.git    -> "juice-shop"
      https://api.github.com/repos/org/repo       -> "repo"
    """
    last = repo_url.rstrip("/").split("/")[-1]
    return last[:-4] if last.endswith(".git") else last


def clone_repo(repo_url: str, base: Path | str = Path("repos")) -> Path:
    """Clone the given repo URL into ROOT_DIR / base / <repo_name>.

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
    """Standard repo acquisition for all scanners.

    If ``repo_path`` is provided: use it, do not clone.
    Else: clone/reuse ``repo_url`` under ``repos_dir``.

    Returns ``TargetRepo(repo_path, repo_name, repo_url, commit)``.
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
