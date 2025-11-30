#!/usr/bin/env python3
"""
scan_sonar.py

Minimal SonarCloud pipeline script for the sast-benchmark-pipeline.

Given a Git repo URL, this script:

  * clones the repo into repos/<name> (reuses if already cloned)
  * runs sonar-scanner CLI on that repo
  * fetches issues for the project via SonarCloud REST API
  * writes:
        runs/sonar/YYYYMMDDXX/<repo_name>.json   (issues)
        runs/sonar/YYYYMMDDXX/metadata.json      (run metadata)

Requirements (outside this script):
  * SonarScanner CLI installed and on PATH
  * SONAR_ORG and SONAR_TOKEN set in the environment
  * optional: SONAR_HOST (default: https://sonarcloud.io)
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

SONAR_HOST_DEFAULT = "https://sonarcloud.io"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run SonarCloud scan on a repo and save JSON + metadata."
    )
    parser.add_argument(
        "--repo-url",
        required=True,
        help="Git URL of the repo (e.g. https://github.com/Chai80/juice-shop.git)",
    )
    parser.add_argument(
        "--output-root",
        default="runs/sonar",
        help="Root folder to store outputs (default: runs/sonar)",
    )
    parser.add_argument(
        "--project-key",
        default=None,
        help="Optional Sonar project key. If omitted, defaults to <SONAR_ORG>_<repo_name>.",
    )
    parser.add_argument(
        "--java-binaries",
        default="",
        help="Optional path to compiled Java classes for sonar.java.binaries "
             "(e.g. target/classes or build/classes).",
    )
    parser.add_argument(
        "--skip-scan",
        action="store_true",
        help="Do not run sonar-scanner; just fetch issues for an existing projectKey.",
    )
    return parser.parse_args()


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
            raise RuntimeError(f"git clone failed with code {resultreturncode}")
    else:
        print(f"✅ Repo already exists, reusing: {path}")

    return path


def validate_sonarcloud_credentials(host: str, org: str, token: str) -> None:
    """Validate token and organization with simple SonarCloud API calls."""
    headers = {"Authorization": f"Bearer {token}"}

    # Validate token
    auth_url = f"{host}/api/authentication/validate"
    resp = requests.get(auth_url, headers=headers, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("valid", False):
        raise RuntimeError("SonarCloud token appears to be invalid (valid=false).")

    # Validate organization
    org_url = f"{host}/api/organizations/search"
    resp = requests.get(
        org_url,
        params={"organizations": org},
        headers=headers,
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    orgs = data.get("organizations", [])
    if not orgs:
        raise RuntimeError(
            f"No organization found for key '{org}'. "
            "Double-check SONAR_ORG in the SonarCloud UI."
        )

    print(f"✅ SonarCloud credentials OK. Organization '{org}' is accessible.")


def create_run_dir(output_root: Path) -> tuple[str, Path]:
    """
    Create a dated run directory like YYYYMMDD01, YYYYMMDD02, ... under output_root.
    """
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
    print(f"📂 Using run directory: {run_dir}")
    return run_id, run_dir


def run_sonar_scan(
    repo_path: Path,
    project_key: str,
    sonar_host: str,
    sonar_org: str,
    sonar_token: str,
    java_binaries: str,
    log_path: Path,
) -> tuple[int, float]:
    """
    Run sonar-scanner in the repo and return (returncode, elapsed_seconds).
    Assumes sonar-scanner is on PATH.
    """
    cmd = [
        "sonar-scanner",
        f"-Dsonar.projectKey={project_key}",
        f"-Dsonar.organization={sonar_org}",
        f"-Dsonar.host.url={sonar_host}",
        f"-Dsonar.token={sonar_token}",
        "-Dsonar.sources=.",
    ]
    if java_binaries:
        cmd.append(f"-Dsonar.java.binaries={java_binaries}")

    print("\n🔍 Running sonar-scanner:")
    print("  cwd:", repo_path)
    print("  command:", " ".join(cmd))

    t0 = time.time()
    with log_path.open("w", encoding="utf-8") as log_file:
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
    elapsed = time.time() - t0
    return result.returncode, elapsed


def wait_for_ce_success(
    host: str,
    org: str,
    project_key: str,
    token: str,
    timeout_sec: int = 300,
) -> None:
    """
    Best-effort wait for SonarCloud Compute Engine to finish processing
    the latest analysis for this project.
    """
    ce_url = f"{host}/api/ce/component"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"component": project_key, "organization": org}

    start = time.time()
    while True:
        try:
            resp = requests.get(ce_url, params=params, headers=headers, timeout=30)
        except requests.RequestException as e:
            print(f"⚠️ CE request error for {project_key}: {e}")
            return

        if resp.status_code == 404:
            print(f"⚠️ CE: project '{project_key}' not found (404). Skipping wait.")
            return
        if not resp.ok:
            print(
                f"⚠️ CE status fetch failed for {project_key}: "
                f"HTTP {resp.status_code} {resp.text[:120]}"
            )
            return

        data = resp.json()
        current = data.get("current")

        if current:
            status = current.get("status")
            if status == "SUCCESS":
                print(f"✅ CE job for {project_key} completed successfully.")
                return
            if status in ("FAILED", "CANCELED"):
                print(f"⚠️ CE job for {project_key} ended with status={status}.")
                return
            print(f"⏳ CE job for {project_key} status={status}, waiting...")
        else:
            print(f"ℹ️ No current CE job for {project_key}, assuming done.")
            return

        if time.time() - start > timeout_sec:
            print(f"⚠️ Timed out waiting for CE job for {project_key}")
            return

        time.sleep(5)


def fetch_all_issues_for_project(
    host: str,
    project_key: str,
    org: str,
    token: str,
) -> list[dict]:
    """Fetch all issues for a given projectKey using paginated API calls."""
    headers = {"Authorization": f"Bearer {token}"}
    all_issues: list[dict] = []
    page = 1
    page_size = 500

    while True:
        params = {
            "componentKeys": project_key,
            "organization": org,
            "ps": page_size,
            "p": page,
        }
        resp = requests.get(
            f"{host}/api/issues/search",
            params=params,
            headers=headers,
            timeout=30,
        )

        if resp.status_code == 404:
            print(f"⚠️ Issues search: project '{project_key}' not found (404).")
            return all_issues

        if resp.status_code == 400 and "Can return only the first 10000 results" in resp.text:
            print(
                f"⚠️ Hit SonarCloud 10k issue limit for {project_key}. "
                f"Returning first {len(all_issues)} issues."
            )
            return all_issues

        resp.raise_for_status()
        data = resp.json()
        issues = data.get("issues", [])
        all_issues.extend(issues)

        if len(issues) < page_size:
            break
        page += 1

    return all_issues


def get_scanner_version() -> str:
    try:
        out = subprocess.check_output(
            ["sonar-scanner", "-v"],
            text=True,
            stderr=subprocess.STDOUT,
        )
        return out.strip()
    except Exception:
        return "unknown"


def main() -> None:
    args = parse_args()

    sonar_host = os.environ.get("SONAR_HOST", SONAR_HOST_DEFAULT)
    sonar_org = os.environ.get("SONAR_ORG")
    sonar_token = os.environ.get("SONAR_TOKEN")

    if not sonar_org:
        print("ERROR: SONAR_ORG environment variable is not set.", file=sys.stderr)
        sys.exit(1)
    if not sonar_token:
        print("ERROR: SONAR_TOKEN environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    print(f"Using Sonar host: {sonar_host}")
    print(f"Using organization: {sonar_org}")

    validate_sonarcloud_credentials(sonar_host, sonar_org, sonar_token)

    repo_base = Path("repos")
    repo_path = clone_repo(args.repo_url, repo_base)
    repo_name = get_repo_name(args.repo_url)

    project_key = args.project_key or f"{sonar_org}_{repo_name}"
    print(f"Sonar project key: {project_key}")

    output_root = Path(args.output_root)
    run_id, run_dir = create_run_dir(output_root)

    log_path = run_dir / f"{repo_name}_sonar_scan.log"

    scan_time = None
    status = "skipped" if args.skip_scan else "success"

    if not args.skip_scan:
        returncode, elapsed = run_sonar_scan(
            repo_path,
            project_key,
            sonar_host,
            sonar_org,
            sonar_token,
            args.java_binaries,
            log_path,
        )
        scan_time = elapsed
        if returncode != 0:
            print(f"⚠️ sonar-scanner failed with code {returncode}. See log: {log_path}")
            status = "scan_failed"
        else:
            print(f"✅ sonar-scanner finished in {elapsed:.2f}s. Log: {log_path}")

    if status == "success":
        wait_for_ce_success(sonar_host, sonar_org, project_key, sonar_token)

    issues = fetch_all_issues_for_project(sonar_host, project_key, sonar_org, sonar_token)
    print(f"📥 Retrieved {len(issues)} issues from SonarCloud")

    results_path = run_dir / f"{repo_name}.json"
    payload = {
        "projectKey": project_key,
        "organization": sonar_org,
        "repo_name": repo_name,
        "scan_time_seconds": scan_time,
        "issue_count": len(issues),
        "issues": issues,
        "run_id": run_id,
        "generated_at": datetime.now().isoformat(),
    }
    with results_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    scanner_version = get_scanner_version()
    metadata = {
        "scanner": "sonar",
        "scanner_kind": "sonar-scanner-cli",
        "scanner_version": scanner_version,
        "host": sonar_host,
        "organization": sonar_org,
        "project_key": project_key,
        "repo_name": repo_name,
        "repo_url": args.repo_url,
        "repo_local_path": str(repo_path),
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "scan_time_seconds": scan_time,
        "issues_count": len(issues),
        "status": status,
        "log_path": str(log_path),
    }
    metadata_path = run_dir / "metadata.json"
    with metadata_path.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("📄 Issues JSON saved to:", results_path)
    print("📄 Metadata saved to:", metadata_path)


if __name__ == "__main__":
    main()
