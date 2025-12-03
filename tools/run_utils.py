# tools/run_utils.py

from __future__ import annotations

import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple

def get_repo_name(repo_url: str) -> str:
    last = repo_url.rstrip("/").split("/")[-1]
    return last[:-4] if last.endswith(".git") else last

def clone_repo(repo_url: str, base: Path | str = Path("repos")) -> Path:
    if not isinstance(base, Path):
        base = Path(base)

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
    try:
        out = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            text=True,
        )
        return out.strip()
    except Exception:
        return "unknown"

def get_commit_author_info(repo_path: Path, commit: str) -> Dict[str, str | None]:
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

def create_run_dir(output_root: Path) -> tuple[str, Path]:
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
