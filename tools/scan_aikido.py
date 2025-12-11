#!/usr/bin/env python3
"""
scan_aikido.py

Aikido pipeline script for the sast-benchmark-pipeline.

Given an Aikido-connected code repository, this script:

  * authenticates against the Aikido public API
  * optionally triggers a scan for the chosen code repo
  * exports all issues via /issues/export and filters for that repo
  * writes:
        runs/aikido/<run_id>/<repo_name>.json             (raw issues list)
        runs/aikido/<run_id>/<repo_name>.normalized.json  (normalized findings)
        runs/aikido/<run_id>/metadata.json                (run metadata)

Notes on timings:
  * For Aikido, we do not see internal engine time.
  * We measure HTTP latency for the /scan trigger call as trigger_http_seconds.
  * In metadata, scan_time_seconds is set equal to trigger_http_seconds so the
    runtime benchmark can compare this field across tools (with this caveat).

Requirements:
  * AIKIDO_CLIENT_ID and AIKIDO_CLIENT_SECRET set in .env at project root
    or in the environment.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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


# ---------------------------------------------------------------------------
# Small data "structs" for config + paths
# ---------------------------------------------------------------------------

@dataclass
class AikidoConfig:
    client_id: str
    client_secret: str
    token: str


@dataclass
class RunPaths:
    run_dir: Path
    raw_results: Path
    normalized: Path
    metadata: Path


# ---------------------------------------------------------------------------
# CLI + config helpers
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Aikido scan and export issues for a connected GitHub repo."
    )
    parser.add_argument(
        "--git-ref",
        required=False,
        help=(
            "Repo name or GitHub URL fragment "
            "(e.g. 'juice-shop' or 'Chai80/juice-shop')"
        ),
    )
    parser.add_argument(
        "--output-root",
        default="runs/aikido",
        help="Root folder for JSON outputs (default: runs/aikido)",
    )
    return parser.parse_args()


def get_aikido_config() -> AikidoConfig:
    """Read Aikido credentials from env and obtain an access token."""
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
    return AikidoConfig(client_id=client_id, client_secret=client_secret, token=token)


def prepare_run_paths(output_root: str, repo_name: str) -> Tuple[str, RunPaths]:
    """
    Create a new run directory.

    Layout:
      runs/aikido/<run_id>/
        - <repo_name>.json
        - <repo_name>.normalized.json
        - metadata.json
    """
    base = Path(output_root)
    run_id, run_dir = create_run_dir(base)

    raw_path = run_dir / f"{repo_name}.json"
    normalized_path = run_dir / f"{repo_name}.normalized.json"
    metadata_path = run_dir / "metadata.json"

    paths = RunPaths(
        run_dir=run_dir,
        raw_results=raw_path,
        normalized=normalized_path,
        metadata=metadata_path,
    )
    return run_id, paths


def write_json(path: Path, data: Any) -> None:
    """Small helper for pretty-printing JSON files."""
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ---------------------------------------------------------------------------
# Aikido API helpers
# ---------------------------------------------------------------------------

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


def trigger_aikido_scan(token: str, code_repo_id: str) -> Optional[float]:
    """
    Trigger an Aikido scan for the given repo.

    Returns:
      trigger_http_seconds (float) or None on failure / no permission.
    """
    headers = {"Authorization": f"Bearer {token}"}
    scan_url = f"{API_ROOT}/repositories/code/{code_repo_id}/scan"

    trigger_http_seconds: Optional[float] = None
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

    return trigger_http_seconds


# ---------------------------------------------------------------------------
# Normalization: Aikido issues → schema v1.1
# ---------------------------------------------------------------------------

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
        # enriched timing / status to match other scanners
        "scan_time_seconds": metadata.get("scan_time_seconds"),
        "exit_code": metadata.get("exit_code"),
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
            # embed full metadata.json content for convenience
            "run_metadata": metadata,
            "findings": [],
        }
        write_json(normalized_path, normalized)
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
        # full run metadata for reference
        "run_metadata": metadata,
        "findings": findings,
    }

    write_json(normalized_path, normalized)


# ---------------------------------------------------------------------------
# Metadata builder
# ---------------------------------------------------------------------------

def build_run_metadata(
    repo_name: str,
    repo_url: Optional[str],
    code_repo_id: str,
    repo_obj: dict,
    run_id: str,
    issues_count: int,
    trigger_http_seconds: Optional[float],
    command_str: str,
) -> dict:
    """Build the metadata.json structure for an Aikido run."""
    return {
        "scanner": "aikido",
        "scanner_version": AIKIDO_TOOL_VERSION,
        "repo_name": repo_name,
        "repo_url": repo_url,
        "code_repo_id": code_repo_id,
        "branch": repo_obj.get("branch"),
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "issues_count": issues_count,
        # Tool-specific timing: HTTP latency when triggering /scan
        "trigger_http_seconds": float(trigger_http_seconds)
        if trigger_http_seconds is not None
        else None,
        # Generic timing field used by benchmarks/runtime.py
        "scan_time_seconds": float(trigger_http_seconds)
        if trigger_http_seconds is not None
        else None,
        "command": command_str,
        # For Aikido there is no CLI exit code; treat as success (0) for consistency.
        "exit_code": 0,
        # We do not currently know commit / author data from Aikido, so leave them None.
        "repo_commit": None,
        "commit_author_name": None,
        "commit_author_email": None,
        "commit_date": None,
    }


# ---------------------------------------------------------------------------
# Top-level pipeline
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    cfg = get_aikido_config()

    # 1. Discover repos from Aikido
    repos = list_code_repos(cfg.token)

    # 2. Choose which repo to use (CLI arg or interactive)
    if args.git_ref:
        git_ref = args.git_ref
    else:
        git_ref = choose_git_ref_interactively(repos)

    code_repo_id, repo_obj = find_repo_by_git_ref(repos, git_ref)
    repo_name = repo_obj.get("name") or "unknown_repo"
    repo_url = repo_obj.get("url")

    # 3. Prepare run directory / paths
    run_id, paths = prepare_run_paths(args.output_root, repo_name)

    # 4. Trigger scan (best effort)
    trigger_http_seconds = trigger_aikido_scan(cfg.token, code_repo_id)

    # 5. Export issues and filter for chosen repo
    all_issues = export_all_issues(cfg.token)
    repo_issues = filter_issues_for_repo(all_issues, code_repo_id)

    write_json(paths.raw_results, repo_issues)

    # Command string for normalized schema: describe the API call we used
    command_str = f"GET {API_ROOT}/issues/export (code_repo_id={code_repo_id})"

    # 6. Build and save metadata
    metadata = build_run_metadata(
        repo_name=repo_name,
        repo_url=repo_url,
        code_repo_id=code_repo_id,
        repo_obj=repo_obj,
        run_id=run_id,
        issues_count=len(repo_issues),
        trigger_http_seconds=trigger_http_seconds,
        command_str=command_str,
    )
    write_json(paths.metadata, metadata)

    print(f"Run {run_id} complete.")
    print(f"  Issues JSON      : {paths.raw_results}")
    print(f"  Metadata         : {paths.metadata}")

    # 7. Normalized JSON
    normalize_aikido_results(paths.raw_results, metadata, paths.normalized)
    print(f"  Normalized JSON  : {paths.normalized}")


if __name__ == "__main__":
    main()
