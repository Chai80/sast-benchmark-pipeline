# tools/run_utils.py

from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict


# Project root = one level up from tools/
# This makes sure "repos" and "runs/..." always live under the repo root,
# no matter where you run the scripts from.
ROOT_DIR = Path(__file__).resolve().parents[1]


def get_repo_name(repo_url: str) -> str:
    """
    Turn a Git URL into a simple repo name.

    Examples:
      https://github.com/juice-shop/juice-shop.git -> "juice-shop"
      https://github.com/vulnerable-apps/dvpwa   -> "dvpwa"
    """
    last = repo_url.rstrip("/").split("/")[-1]
    return last[:-4] if last.endswith(".git") else last


def clone_repo(repo_url: str, base: Path | str = Path("repos")) -> Path:
    """
    Clone the given repo URL into ROOT_DIR / base / <repo_name>.

    If the repo already exists locally, it is reused.
    """
    # Normalize base to a Path
    if not isinstance(base, Path):
        base = Path(base)

    # Anchor relative bases under the project root
    if not base.is_absolute():
        base = ROOT_DIR / base

    base.mkdir(parents=True, exist_ok=True)
    name = get_repo_name(repo_url)
    path = base / name

    if not path.exists():
        print(f"📥 Cloning {name} from {repo_url} ...")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(path)],
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed with code {result.returncode}")
    else:
        print(f"✅ Repo already exists, reusing: {path}")

    return path


def get_git_commit(path: Path) -> str:
    """
    Return the current commit SHA for the repo at 'path'.
    """
    try:
        out = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            text=True,
        )
        return out.strip()
    except Exception:
        return "unknown"


def get_commit_author_info(repo_path: Path, commit: str) -> Dict[str, str | None]:
    """
    Return author name/email/date for the given commit SHA in the repo.
    """
    try:
        out = subprocess.check_output(
            [
                "git",
                "-C",
                str(repo_path),
                "show",
                "-s",
                "--format=%an%n%ae%n%aI",
                commit,
            ],
            text=True,
        )
        lines = out.splitlines()
        return {
            "commit_author_name": lines[0] if len(lines) > 0 else None,
            "commit_author_email": lines[1] if len(lines) > 1 else None,
            "commit_date": lines[2] if len(lines) > 2 else None,
        }
    except subprocess.CalledProcessError:
        return {
            "commit_author_name": None,
            "commit_author_email": None,
            "commit_date": None,
        }


def create_run_dir(output_root: Path | str) -> tuple[str, Path]:
    """
    Create a dated run directory like YYYYMMDD01, YYYYMMDD02, ... under output_root.

    If output_root is relative (e.g. 'runs/semgrep'), it is anchored under ROOT_DIR,
    so the final path is ROOT_DIR / output_root / <run_id>.
    """
    # Normalize to a Path
    if not isinstance(output_root, Path):
        output_root = Path(output_root)

    # Anchor relative roots under the project root
    if not output_root.is_absolute():
        output_root = ROOT_DIR / output_root

    today = datetime.now().strftime("%Y%m%d")
    output_root.mkdir(parents=True, exist_ok=True)

    existing = [
        d.name
        for d in output_root.iterdir()
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
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    print("📂 Using run directory:", run_dir)
    return run_id, run_dir
