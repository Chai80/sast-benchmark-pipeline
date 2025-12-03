#!/usr/bin/env python3
"""
scan_aikido.py

Aikido pipeline script for the sast-benchmark-pipeline.

Given an Aikido-connected code repository, this script:

  * authenticates against the Aikido public API
  * optionally triggers a scan for the chosen code repo
  * exports all issues via /issues/export and filters for that repo
  * writes:
        runs/aikido/YYYYMMDDXX/<repo_name>.json             (raw issues list)
        runs/aikido/YYYYMMDDXX/<repo_name>.normalized.json  (normalized findings)
        runs/aikido/YYYYMMDDXX/metadata.json                (run metadata)

Requirements:
  * AIKIDO_CLIENT_ID and AIKIDO_CLIENT_SECRET set in .env at project root or in the environment
"""

import argparse
import base64
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv

# Shared helper for run directories
from run_utils import create_run_dir

TOKEN_URL = "https://app.aikido.dev/api/oauth/token"
API_ROOT = "https://app.aikido.dev/api/public/v1"
AIKIDO_TOOL_VERSION = "public-api-v1"

# Load .env from project root (one level up from tools/)
ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")


def get_access_token(client_id: str, client_secret: str) -> str:
    basic = f"{client_id}:{client_secret}".encode("utf-8")
    headers = {
        "Authorization": "Basic " + base64.b64encode(basic).decode("ascii"),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {"grant_type": "client_credentials"}
    resp = requests.post(TOKEN_URL, headers=headers, data=data, timeout=30)
    resp.raise_for_status()
    return resp.json()["access_token"]


def list_code_repos(token: str) -> list[dict]:
    """Return all Aikido code repos for this workspace."""
    url = f"{API_ROOT}/repositories/code"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data["data"] if isinstance(data, dict) and "data" in data else data


def choose_git_ref_interactively(repos: list[dict]) -> str:
    """Show a numbered menu [1–N] and return the chosen repo's git_ref (name or URL)."""
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


def find_repo_by_git_ref(repos: list[dict], git_ref: str) -> tuple[str, dict]:
    """Find an Aikido repo by name or GitHub URL fragment."""
    needle = git_ref.strip().lower()
    for r in repos:
        name = (r.get("name") or "").lower()
        url = (r.get("url") or "").lower()
        if needle == name or needle.endswith("/" + name) or needle in url:
            return str(r["id"]), r
    raise ValueError(f"No Aikido repo found for {git_ref!r}")


def export_all_issues(token: str) -> list[dict]:
    """Export all issues from Aikido."""
    url = f"{API_ROOT}/issues/export"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    return data["data"] if isinstance(data, dict) and "data" in data else data


def filter_issues_for_repo(issues: list[dict], code_repo_id: str) -> list[dict]:
    """Return only issues belonging to the given Aikido code_repo_id."""
    return [issue for issue in issues if str(issue.get("code_repo_id")) == str(code_repo_id)]


def normalize_aikido_results(
    raw_results_path: Path,
    metadata: dict,
    normalized_path: Path,
) -> None:
    """
    Convert Aikido issues JSON into the common normalized schema (schema v1.1).

    raw_results_path is expected to contain a JSON array of issues for a single
    code_repo_id (what this script writes to <repo_name>.json).
    """
    target_repo = {
        "name": metadata.get("repo_name"),
        "url": metadata.get("repo_url"),
        "commit": metadata.get("repo_commit"),
        "commit_author_name": metadata.get("commit_author_name"),
        "commit_author_email": metadata.get("commit_author_email"),
        "commit_date": metadata.get("commit_date"),
    }
    scan_info = {
        "run_id": metadata.get("run_id"),
        "scan_date": metadata.get("timestamp"),
        "command": metadata.get("command"),
        "raw_results_path": str(raw_results_path),
        "metadata_path": "metadata.json",
    }
    per_finding_metadata = {
        "tool": "aikido",
        "tool_version": metadata.get("scanner_version"),
        "target_repo": target_repo,
        "scan": scan_info,
    }

    if not raw_results_path.exists():
        normalized = {
            "schema_version": "1.1",
            "tool": "aikido",
            "tool_version": metadata.get("scanner_version"),
            "target_repo": target_repo,
            "scan": scan_info,
            "findings": [],
        }
        with normalized_path.open("w", encoding="utf-8") as f:
            json.dump(normalized, f, indent=2)
        return

    with raw_results_path.open("r", encoding="utf-8") as f:
        issues = json.load(f)

    if not isinstance(issues, list):
        # Defensive: if the API ever changes to return an object
        issues = issues.get("data") or []

    findings: list[dict] = []

    for issue in issues:
        issue_id = issue.get("id")

        # Best-effort extraction of rule/identifier
        rule_id = (
            issue.get("rule_id")
            or issue.get("rule")
            or issue.get("type")
            or issue.get("category")
        )

        # Title/summary/message
        title = (
            issue.get("title")
            or issue.get("summary")
            or issue.get("message")
            or (f"Aikido issue {issue_id}" if issue_id is not None else None)
        )

        # Severity mapping (HIGH/MEDIUM/LOW)
        severity_raw = (
            (issue.get("severity") or issue.get("risk") or "").strip().upper()
        )
        if severity_raw in ("CRITICAL", "HIGH"):
            severity = "HIGH"
        elif severity_raw in ("MEDIUM", "MODERATE"):
            severity = "MEDIUM"
        elif severity_raw in ("LOW", "INFO", "INFORMATIONAL"):
            severity = "LOW"
        else:
            severity = None

        # CWE (if present)
        cwe = issue.get("cwe") or issue.get("cwe_id")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        cwe_id = None
        if cwe:
            cwe_str = str(cwe).upper()
            if cwe_str.startswith("CWE-"):
                cwe_id = cwe_str
            else:
                cwe_id = f"CWE-{cwe_str}"

        # File path and line number (if provided by Aikido)
        file_path = (
            issue.get("file_path")
            or issue.get("file")
            or issue.get("path")
        )
        line = issue.get("line") or issue.get("line_number")
        end_line = line

        finding = {
            "metadata": per_finding_metadata,
            "finding_id": f"aikido:{issue_id or rule_id}:{file_path}:{line}",
            "cwe_id": cwe_id,
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "file_path": file_path,
            "line_number": line,
            "end_line_number": end_line,
            "line_content": None,  # we do not have local source code here
            "vendor": {
                "raw_result": issue,
            },
        }
        findings.append(finding)

    normalized = {
        "schema_version": "1.1",
        "tool": "aikido",
        "tool_version": metadata.get("scanner_version"),
        "target_repo": target_repo,
        "scan": scan_info,
        "findings": findings,
    }

    with normalized_path.open("w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2)


def main() -> None:
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
        print(
            "ERROR: set AIKIDO_CLIENT_ID and AIKIDO_CLIENT_SECRET env vars "
            "(or in .env at project root).",
            file=sys.stderr,
        )
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
    repo_url = repo_obj.get("url")

    # Run directory (shared helper)
    output_root = Path(args.output_root)
    run_id, run_dir = create_run_dir(output_root)

    headers = {"Authorization": f"Bearer {token}"}
    scan_url = f"{API_ROOT}/repositories/code/{code_repo_id}/scan"
    trigger_http_seconds: float | None = None

    try:
        t0 = time.time()
        resp = requests.post(scan_url, headers=headers, timeout=30)
        if resp.status_code == 403:
            print(
                "No permission to trigger scan; using latest existing results.",
                file=sys.stderr,
            )
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

    # Command string for normalized schema: describe the API call we used
    command_str = f"GET {API_ROOT}/issues/export (code_repo_id={code_repo_id})"

    metadata = {
        "scanner": "aikido",
        "scanner_version": AIKIDO_TOOL_VERSION,
        "repo_name": repo_name,
        "repo_url": repo_url,
        "code_repo_id": code_repo_id,
        "branch": repo_obj.get("branch"),
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "issues_count": len(repo_issues),
        "trigger_http_seconds": float(trigger_http_seconds)
        if trigger_http_seconds is not None
        else None,
        "command": command_str,
        # We do not currently know commit / author data from Aikido, so leave them None.
        "repo_commit": None,
        "commit_author_name": None,
        "commit_author_email": None,
        "commit_date": None,
    }
    metadata_path = run_dir / "metadata.json"
    with metadata_path.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Run {run_id} complete.")
    print(f"  Issues JSON      : {results_path}")
    print(f"  Metadata         : {metadata_path}")

    # Normalized JSON
    normalized_path = run_dir / f"{repo_name}.normalized.json"
    normalize_aikido_results(results_path, metadata, normalized_path)
    print(f"  Normalized JSON  : {normalized_path}")


if __name__ == "__main__":
    main()
