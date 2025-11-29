#!/usr/bin/env python3
import argparse
import json
import subprocess
import time
from datetime import datetime
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser(
        description="Run Semgrep on a repo and save JSON + metadata."
    )
    p.add_argument(
        "--repo-url",
        required=True,
        help="Git URL of the repo to scan (e.g. https://github.com/juice-shop/juice-shop.git)",
    )
    p.add_argument(
        "--output-root",
        default="runs/semgrep",
        help="Root folder to store outputs (default: runs/semgrep)",
    )
    p.add_argument(
        "--config",
        default="p/security-audit",
        help="Semgrep config to use (default: p/security-audit)",
    )
    return p.parse_args()


def get_repo_name(repo_url: str) -> str:
    last = repo_url.rstrip("/").split("/")[-1]
    return last[:-4] if last.endswith(".git") else last


def clone_repo(repo_url: str, base: Path) -> Path:
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


def main():
    args = parse_args()

    # 1. Clone repo
    repo_base = Path("repos")
    repo_path = clone_repo(args.repo_url, repo_base)
    repo_name = get_repo_name(args.repo_url)

    # 2. Prepare output paths
    output_root = Path(args.output_root)
    run_id, run_dir = create_run_dir(output_root)

    results_path = run_dir / f"{repo_name}.json"
    metadata_path = run_dir / "metadata.json"

    # 3. Run Semgrep
    print(f"\n🔍 Running Semgrep on {repo_name} ...")
    t0 = time.time()
    cmd = [
        "semgrep",
        "--config",
        args.config,
        "--json",
        "--quiet",
        "--output",
        str(results_path),
        str(repo_path),
    ]
    print("Command:", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - t0

    if result.returncode != 0:
        print(f"⚠️ Semgrep failed with code {result.returncode}")
        print(result.stderr[:2000])
        return

    print(f"✅ Semgrep finished in {elapsed:.2f}s")
    print("JSON saved to:", results_path)

    # 4. Build metadata
    commit = get_git_commit(repo_path)
    scanner_version = subprocess.check_output(["semgrep", "--version"], text=True).strip()
    metadata = {
        "scanner": "semgrep",
        "scanner_version": scanner_version,
        "repo_name": repo_name,
        "repo_url": args.repo_url,
        "repo_commit": commit,
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "command": " ".join(cmd),
        "scan_time_seconds": elapsed,
    }
    with metadata_path.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("📄 Metadata saved to:", metadata_path)


if __name__ == "__main__":
    main()
