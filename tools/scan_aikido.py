#!/usr/bin/env python3
import argparse
import base64
import datetime
import json
import os
import sys
import time
from pathlib import Path

import requests

TOKEN_URL = "https://app.aikido.dev/api/oauth/token"
API_ROOT = "https://app.aikido.dev/api/public/v1"


def get_access_token(client_id, client_secret):
    basic = f"{client_id}:{client_secret}".encode("utf-8")
    headers = {
        "Authorization": "Basic " + base64.b64encode(basic).decode("ascii"),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {"grant_type": "client_credentials"}
    resp = requests.post(TOKEN_URL, headers=headers, data=data)
    resp.raise_for_status()
    return resp.json()["access_token"]


def list_code_repos(token):
    """Return all Aikido code repos for this workspace."""
    url = f"{API_ROOT}/repositories/code"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    repos = data["data"] if isinstance(data, dict) and "data" in data else data
    return repos


def choose_git_ref_interactively(repos):
    """Show a numbered menu [1–N] and return the chosen repo's git_ref (name)."""
    print("Available Aikido code repos:")
    for idx, r in enumerate(repos, start=1):
        print(
            f"[{idx}] id={r['id']} | "
            f"name={r.get('name')} | "
            f"url={r.get('url')}"
        )

    while True:
        choice = input(f"Enter the number of the repo to scan (1-{len(repos)}): ").strip()
        try:
            idx = int(choice)
            if 1 <= idx <= len(repos):
                selected = repos[idx - 1]
                git_ref = selected.get("name") or selected.get("url")
                print(f"Selected repo: {git_ref}")
                return git_ref
        except ValueError:
            pass
        print("Invalid choice, please try again.")


def find_repo_by_git_ref(repos, git_ref: str):
    """Find an Aikido repo by name or GitHub URL fragment."""
    git_ref = git_ref.strip().lower()
    for r in repos:
        name = (r.get("name") or "").lower()
        url = (r.get("url") or "").lower()
        if git_ref == name or git_ref.endswith("/" + name) or git_ref in url:
            return r["id"], r
    raise ValueError(f"No Aikido repo found for {git_ref}")


def export_all_issues(token):
    """Export all issues from Aikido."""
    url = f"{API_ROOT}/issues/export"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    return data["data"] if isinstance(data, dict) and "data" in data else data


def filter_issues_for_repo(issues, code_repo_id):
    """Return only issues belonging to the given Aikido code_repo_id."""
    return [issue for issue in issues if issue.get("code_repo_id") == code_repo_id]


def create_run_dir(output_root: Path):
    """Create a dated run directory like YYYYMMDD01 under output_root."""
    output_root.mkdir(parents=True, exist_ok=True)
    today = datetime.datetime.now().strftime("%Y%m%d")
    existing = [
        d.name for d in output_root.iterdir()
        if d.is_dir() and d.name.startswith(today)
    ]
    if not existing:
        idx = 1
    else:
        try:
            idx = max(int(name[-2:]) for name in existing) + 1
        except ValueError:
            idx = len(existing) + 1
    run_id = f"{today}{idx:02d}"
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_id, run_dir


def main():
    parser = argparse.ArgumentParser(
        description="Run Aikido scan and export issues for a connected GitHub repo."
    )
    parser.add_argument(
        "--git-ref",
        required=False,
        help="Repo name or GitHub URL fragment (e.g. 'juice-shop' or 'Chai80/juice-shop')",
    )
    parser.add_argument(
        "--output-root",
        default="runs/aikido",
        help="Root folder for JSON outputs (default: runs/aikido)",
    )
    args = parser.parse_args()

    client_id = os.getenv("AIKIDO_CLIENT_ID")
    client_secret = os.getenv("AIKIDO_CLIENT_SECRET")
    if not client_id or not client_secret:
        print("ERROR: set AIKIDO_CLIENT_ID and AIKIDO_CLIENT_SECRET env vars.", file=sys.stderr)
        sys.exit(1)

    token = get_access_token(client_id, client_secret)

    # Get all repos from Aikido
    repos = list_code_repos(token)

    # Decide which repo to scan: CLI flag or interactive menu
    if args.git_ref:
        git_ref = args.git_ref
    else:
        git_ref = choose_git_ref_interactively(repos)

    code_repo_id, repo_obj = find_repo_by_git_ref(repos, git_ref)
    repo_name = repo_obj.get("name") or "unknown_repo"

    output_root = Path(args.output_root)
    run_id, run_dir = create_run_dir(output_root)

    headers = {"Authorization": f"Bearer {token}"}
    scan_url = f"{API_ROOT}/repositories/code/{code_repo_id}/scan"
    trigger_http_seconds = None
    try:
        t0 = time.time()
        resp = requests.post(scan_url, headers=headers)
        if resp.status_code == 403:
            print("No permission to trigger scan; using latest existing results.", file=sys.stderr)
        else:
            resp.raise_for_status()
            trigger_http_seconds = time.time() - t0
    except Exception as e:
        print(f"Warning: scan trigger failed: {e}", file=sys.stderr)

    all_issues = export_all_issues(token)
    repo_issues = filter_issues_for_repo(all_issues, code_repo_id)

    results_path = run_dir / f"{repo_name}.json"
    with results_path.open("w", encoding="utf-8") as f:
        json.dump(repo_issues, f, indent=2)

    metadata = {
        "scanner": "aikido",
        "repo_name": repo_name,
        "code_repo_id": code_repo_id,
        "external_repo_url": repo_obj.get("url"),
        "branch": repo_obj.get("branch"),
        "run_id": run_id,
        "timestamp": datetime.datetime.now().isoformat(),
        "issues_count": len(repo_issues),
        "trigger_http_seconds": float(trigger_http_seconds)
        if trigger_http_seconds is not None
        else None,
    }
    with (run_dir / "metadata.json").open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Run {run_id} complete.")
    print(f"  Issues JSON : {results_path}")
    print(f"  Metadata    : {run_dir / 'metadata.json'}")


if __name__ == "__main__":
    main()
