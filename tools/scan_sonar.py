#!/usr/bin/env python3
"""
scan_sonar.py

SonarCloud pipeline script for the sast-benchmark-pipeline.

Given a Git repo URL, this script:

  * clones the repo into repos/<name> (reuses if already cloned)
  * runs sonar-scanner CLI on that repo (unless --skip-scan)
  * fetches issues for the project via SonarCloud REST API
  * enriches each finding with CWE + OWASP Top 10 classification
    using SonarCloud /api/rules/show
  * writes (grouped by repo name):
        runs/sonar/<repo_name>/<run_id>/<repo_name>.json
        runs/sonar/<repo_name>/<run_id>/<repo_name>.normalized.json
        runs/sonar/<repo_name>/<run_id>/metadata.json

Requirements (outside this script):
  * SonarScanner CLI installed and on PATH
  * SONAR_ORG and SONAR_TOKEN set in the environment (or in .env)
  * optional: SONAR_HOST (default: https://sonarcloud.io)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from dotenv import load_dotenv

# Shared helpers used across scan_* tools
from run_utils import (
    get_repo_name,
    clone_repo,
    get_git_commit,
    get_commit_author_info,
    create_run_dir,
)

SONAR_HOST_DEFAULT = "https://sonarcloud.io"

# Load .env from project root (one level up from tools/)
ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")


# ---------------------------------------------------------------------------
# Simple data "structs" for config and paths
# ---------------------------------------------------------------------------

@dataclass
class SonarConfig:
    host: str
    org: str
    token: str


@dataclass
class RunPaths:
    run_dir: Path
    log: Path
    raw_results: Path
    normalized: Path
    metadata: Path


# ---------------------------------------------------------------------------
# OWASP Top 10 mappings (used when enriching rules)
# ---------------------------------------------------------------------------

# OWASP Top 10 2021 mapping (A01..A10 → human name)
OWASP_TOP_10_2021_NAMES: Dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

# OWASP Top 10 2017 mapping (A1..A10 → human name)
OWASP_TOP_10_2017_NAMES: Dict[str, str] = {
    "A1": "Injection",
    "A2": "Broken Authentication",
    "A3": "Sensitive Data Exposure",
    "A4": "XML External Entities (XXE)",
    "A5": "Broken Access Control",
    "A6": "Security Misconfiguration",
    "A7": "Cross-Site Scripting (XSS)",
    "A8": "Insecure Deserialization",
    "A9": "Using Components with Known Vulnerabilities",
    "A10": "Insufficient Logging & Monitoring",
}


# ---------------------------------------------------------------------------
# CLI + config helpers
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run SonarCloud scan on a repo and save JSON + metadata + normalized output."
    )
    parser.add_argument(
        "--repo-url",
        required=True,
        help="Git URL of the repo (e.g. https://github.com/juice-shop/juice-shop.git)",
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
        help=(
            "Optional path to compiled Java classes for sonar.java.binaries "
            "(e.g. target/classes or build/classes)."
        ),
    )
    parser.add_argument(
        "--skip-scan",
        action="store_true",
        help="Do not run sonar-scanner; just fetch issues for an existing projectKey.",
    )
    return parser.parse_args()


def get_sonar_token() -> str:
    token = os.getenv("SONAR_TOKEN")
    if not token:
        print(
            "ERROR: SONAR_TOKEN environment variable is not set.\n"
            "Add it to your .env or export it in your shell before running.",
            file=sys.stderr,
        )
        sys.exit(1)
    return token


def get_sonar_config() -> SonarConfig:
    """Read SONAR_* env vars and fail early if something important is missing."""
    host = os.environ.get("SONAR_HOST", SONAR_HOST_DEFAULT)
    org = os.environ.get("SONAR_ORG")
    token = get_sonar_token()

    if not org:
        print("ERROR: SONAR_ORG environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    return SonarConfig(host=host, org=org, token=token)


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


def prepare_repo(repo_url: str, repos_root: Path = Path("repos")) -> Tuple[Path, str]:
    """Clone (or reuse) the repo and return (repo_path, repo_name)."""
    repo_path = clone_repo(repo_url, repos_root)
    repo_name = get_repo_name(repo_url)
    return repo_path, repo_name


def prepare_run_paths(output_root: str, repo_name: str) -> Tuple[str, RunPaths]:
    """
    Create a new run directory for this repo and return (run_id, paths).

    Layout:

      runs/sonar/<repo_name>/<run_id>/
        - <repo_name>_sonar_scan.log
        - <repo_name>.json
        - <repo_name>.normalized.json
        - metadata.json
    """
    base = Path(output_root) / repo_name
    run_id, run_dir = create_run_dir(base)

    log_path = run_dir / f"{repo_name}_sonar_scan.log"
    raw_path = run_dir / f"{repo_name}.json"
    normalized_path = run_dir / f"{repo_name}.normalized.json"
    metadata_path = run_dir / "metadata.json"

    paths = RunPaths(
        run_dir=run_dir,
        log=log_path,
        raw_results=raw_path,
        normalized=normalized_path,
        metadata=metadata_path,
    )
    return run_id, paths


def write_json(path: Path, data: Dict[str, Any]) -> None:
    """Small helper for pretty-printing JSON files."""
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ---------------------------------------------------------------------------
# Running sonar-scanner + CE wait + issues fetch
# ---------------------------------------------------------------------------

def run_sonar_scan(
    repo_path: Path,
    project_key: str,
    sonar_host: str,
    sonar_org: str,
    sonar_token: str,
    java_binaries: str,
    log_path: Path,
) -> Tuple[int, float, List[str]]:
    """
    Run sonar-scanner in the repo and return (returncode, elapsed_seconds, cmd).
    Assumes sonar-scanner is on PATH.
    """
    cmd = [
        "sonar-scanner",
        f"-Dsonar.projectKey={project_key}",
        f"-Dsonar.organization={sonar_org}",
        f"-Dsonar.host.url={sonar_host}",
        "-Dsonar.sources=.",
    ]
    if java_binaries:
        cmd.append(f"-Dsonar.java.binaries={java_binaries}")

    print("\n🔍 Running sonar-scanner:")
    print("  cwd:", repo_path)
    print("  command:", " ".join(cmd))  # token is NOT printed

    env = dict(os.environ)
    env["SONAR_TOKEN"] = sonar_token  # scanner reads token from env

    t0 = time.time()
    try:
        with log_path.open("w", encoding="utf-8") as log_file:
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
            )
    except FileNotFoundError:
        raise RuntimeError(
            "sonar-scanner CLI not found on PATH. "
            "Install the SonarScanner CLI and make sure `sonar-scanner -v` works."
        )

    elapsed = time.time() - t0
    return result.returncode, elapsed, cmd


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
) -> List[Dict[str, Any]]:
    """
    Fetch all issues for a given projectKey using paginated API calls.

    This is best-effort:
      * 404 → project not found, return whatever we have (usually empty)
      * 400 "first 10000 results" → stop and return partial list
      * 5xx / network errors → log warning, stop and return partial list
    """
    headers = {"Authorization": f"Bearer {token}"}
    all_issues: List[Dict[str, Any]] = []
    page = 1
    page_size = 500

    while True:
        params = {
            "componentKeys": project_key,
            "organization": org,
            "ps": page_size,
            "p": page,
        }

        try:
            resp = requests.get(
                f"{host}/api/issues/search",
                params=params,
                headers=headers,
                timeout=30,
            )
        except requests.RequestException as e:
            print(
                f"⚠️ Issues search request error for {project_key} page {page}: {e}. "
                f"Returning {len(all_issues)} issues collected so far."
            )
            break

        # Project not found → nothing to do
        if resp.status_code == 404:
            print(f"⚠️ Issues search: project '{project_key}' not found (404).")
            break

        # Hit SonarCloud's 10k issue limit
        if resp.status_code == 400 and "Can return only the first 10000 results" in resp.text:
            print(
                f"⚠️ Hit SonarCloud 10k issue limit for {project_key} on page {page}. "
                f"Returning first {len(all_issues)} issues."
            )
            break

        # 5xx or other server-side errors → keep what we have
        if 500 <= resp.status_code < 600:
            print(
                f"⚠️ Issues search server error {resp.status_code} for {project_key} "
                f"page {page}: {resp.text[:200]!r}. "
                f"Returning {len(all_issues)} issues collected so far."
            )
            break

        # Any other non-OK → log and stop
        if not resp.ok:
            print(
                f"⚠️ Issues search HTTP {resp.status_code} for {project_key} "
                f"page {page}: {resp.text[:200]!r}. "
                f"Returning {len(all_issues)} issues collected so far."
            )
            break

        try:
            data = resp.json()
        except ValueError:
            print(
                f"⚠️ Could not decode JSON for {project_key} page {page}. "
                f"Returning {len(all_issues)} issues collected so far."
            )
            break

        issues = data.get("issues", []) or []
        all_issues.extend(issues)

        if len(issues) < page_size:
            # Last page (fewer than page_size issues)
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


# ---------------------------------------------------------------------------
# Rules classification helpers (CWE + OWASP)
# ---------------------------------------------------------------------------

def build_owasp_block(
    codes: List[str],
    names_map: Dict[str, str],
    year_label: str,
) -> Optional[Dict[str, Any]]:
    """
    Build a block like:

      {
        "codes": ["A03"],
        "categories": ["A03:2021-Injection"]
      }

    or return None if codes is empty.
    """
    codes = codes or []
    if not codes:
        return None

    categories: List[str] = []
    for code in codes:
        code_str = code.strip()
        if not code_str:
            continue
        name = names_map.get(code_str, "Unknown")
        categories.append(f"{code_str}:{year_label}-{name}")
    if not categories:
        return None
    return {"codes": codes, "categories": categories}


def fetch_rule_classification(
    host: str,
    organization: Optional[str],
    token: str,
    rule_key: str,
) -> Optional[Dict[str, Any]]:
    """
    Query SonarCloud for a single rule's metadata and derive:
      - cwe_ids
      - owasp_top_10_2017
      - owasp_top_10_2021
      - vuln_class (rule name)

    Returns None on failure (network, 404, etc.).
    """
    base_url = host.rstrip("/") + "/api/rules/show"
    params: Dict[str, Any] = {"key": rule_key}
    if organization:
        params["organization"] = organization

    headers = {"Authorization": f"Bearer {token}"}

    try:
        resp = requests.get(base_url, params=params, headers=headers, timeout=15)
    except requests.RequestException as e:
        print(
            f"⚠️ Failed to fetch rule metadata for {rule_key}: {e}",
            file=sys.stderr,
        )
        return None

    if resp.status_code == 404:
        print(f"⚠️ Rule {rule_key} not found in Sonar (404); skipping.", file=sys.stderr)
        return None
    if not resp.ok:
        print(
            f"⚠️ Rule metadata HTTP {resp.status_code} for {rule_key}: "
            f"{resp.text[:200]!r}",
            file=sys.stderr,
        )
        return None

    try:
        data = resp.json()
    except ValueError:
        print(
            f"⚠️ Could not decode JSON rules/show response for {rule_key}",
            file=sys.stderr,
        )
        return None

    rule = data.get("rule") or {}
    name = rule.get("name")  # descriptive rule name → vuln_class
    tags = rule.get("tags") or []
    security_standards = rule.get("securityStandards") or []

    cwe_ids: List[str] = []
    owasp2017_codes: List[str] = []
    owasp2021_codes: List[str] = []

    # --- 1) Parse securityStandards (can be dict OR list of strings) ---

    if isinstance(security_standards, dict):
        # Shape: {"CWE": ["79"], "OWASP Top 10 2021": ["A03"], ...}
        for c in security_standards.get("CWE", []) or []:
            c_str = str(c).strip()
            if not c_str:
                continue
            cwe_ids.append(f"CWE-{c_str}")

        owasp2017_codes = list(security_standards.get("OWASP Top 10 2017", []) or [])
        owasp2021_codes = list(security_standards.get("OWASP Top 10 2021", []) or [])

    elif isinstance(security_standards, list):
        # Common SonarCloud shape: ["cwe:79", "owaspTop10:a1", "owaspTop10-2021:a03", ...]
        for entry in security_standards:
            if not isinstance(entry, str):
                continue
            lower = entry.lower()

            # CWE entries: "cwe:79"
            if lower.startswith("cwe:"):
                num = entry.split(":", 1)[1].strip()
                if num:
                    cwe_ids.append(f"CWE-{num.upper()}")
                continue

            # OWASP 2021: "owasptop10-2021:a03"
            if "owasptop10-2021" in lower:
                code_part = entry.split(":", 1)[1].strip() if ":" in entry else ""
                if code_part:
                    code = code_part.upper()
                    # normalize "03" → "A03"
                    if not code.startswith("A"):
                        code = "A" + code
                    owasp2021_codes.append(code)
                continue

            # OWASP 2017: "owasptop10:a1" or "owasptop10-2017:a1"
            if "owasptop10-2017" in lower or "owasptop10:" in lower:
                code_part = entry.split(":", 1)[1].strip() if ":" in entry else ""
                if code_part:
                    code = code_part.upper()
                    if not code.startswith("A"):
                        code = "A" + code
                    owasp2017_codes.append(code)
                continue

    # --- 2) Fallback CWE from tags (e.g. "cwe-89") ---

    for t in tags:
        if not isinstance(t, str):
            continue
        lower = t.lower()
        if lower.startswith("cwe-"):
            num = lower.split("cwe-", 1)[1]
            if num:
                cid = f"CWE-{num.upper()}"
                cwe_ids.append(cid)

    # De-duplicate CWE list while preserving order
    seen_cwe: Set[str] = set()
    deduped_cwe_ids: List[str] = []
    for cid in cwe_ids:
        if cid not in seen_cwe:
            seen_cwe.add(cid)
            deduped_cwe_ids.append(cid)
    cwe_ids = deduped_cwe_ids

    # De-duplicate OWASP code lists
    owasp2017_codes = list(dict.fromkeys(owasp2017_codes))
    owasp2021_codes = list(dict.fromkeys(owasp2021_codes))

    # --- 3) Build OWASP blocks with human-readable labels ---

    owasp_2017_block = build_owasp_block(
        owasp2017_codes,
        OWASP_TOP_10_2017_NAMES,
        "2017",
    )
    owasp_2021_block = build_owasp_block(
        owasp2021_codes,
        OWASP_TOP_10_2021_NAMES,
        "2021",
    )

    return {
        "rule_key": rule_key,
        "vuln_class": name,
        "cwe_ids": cwe_ids,
        "owasp_top_10_2017": owasp_2017_block,
        "owasp_top_10_2021": owasp_2021_block,
    }


# ---------------------------------------------------------------------------
# Building raw issues payload + metadata
# ---------------------------------------------------------------------------

def build_issues_payload(
    project_key: str,
    cfg: SonarConfig,
    repo_name: str,
    issues: List[Dict[str, Any]],
    run_id: str,
    scan_time: Optional[float],
) -> Dict[str, Any]:
    """Build the JSON object we store in <repo_name>.json."""
    return {
        "projectKey": project_key,
        "organization": cfg.org,
        "repo_name": repo_name,
        "scan_time_seconds": scan_time,
        "issue_count": len(issues),
        "issues": issues,
        "run_id": run_id,
        "generated_at": datetime.now().isoformat(),
    }


def build_run_metadata(
    cfg: SonarConfig,
    repo_path: Path,
    repo_name: str,
    repo_url: str,
    project_key: str,
    run_id: str,
    issues: List[Dict[str, Any]],
    scan_time: Optional[float],
    status: str,
    paths: RunPaths,
    command_str: Optional[str],
    exit_code: Optional[int],
) -> Dict[str, Any]:
    """Collect commit + scanner + run info into metadata.json."""
    scanner_version = get_scanner_version()
    commit = get_git_commit(repo_path)
    author_info = get_commit_author_info(repo_path, commit)

    return {
        "scanner": "sonar",
        "scanner_kind": "sonar-scanner-cli",
        "scanner_version": scanner_version,
        "host": cfg.host,
        "organization": cfg.org,
        "project_key": project_key,
        "repo_name": repo_name,
        "repo_url": repo_url,
        "repo_local_path": str(repo_path),
        "repo_commit": commit,
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "scan_time_seconds": scan_time,
        "issues_count": len(issues),
        "status": status,
        "log_path": str(paths.log),
        "command": command_str,
        "exit_code": exit_code,
        **author_info,
    }


# ---------------------------------------------------------------------------
# Normalization (Sonar issues JSON → schema v1.1)
# ---------------------------------------------------------------------------

def normalize_sonar_results(
    repo_path: Path,
    raw_results_path: Path,
    metadata: Dict[str, Any],
    normalized_path: Path,
    sonar_host: str,
    sonar_org: str,
    sonar_token: str,
) -> None:
    """
    Convert Sonar issues JSON into the common normalized schema (schema v1.1),
    enriched with CWE + OWASP Top 10 classification via SonarCloud rules API.

    raw_results_path is expected to contain a JSON object like:
      {
        "projectKey": ...,
        "organization": ...,
        "repo_name": ...,
        "scan_time_seconds": ...,
        "issue_count": ...,
        "issues": [ { ... }, ... ],
        ...
      }
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
        # enriched with performance / status info from metadata.json
        "scan_time_seconds": metadata.get("scan_time_seconds"),
        "exit_code": metadata.get("exit_code"),
        "metadata_path": "metadata.json",
    }
    per_finding_metadata = {
        "tool": "sonar",
        "tool_version": metadata.get("scanner_version"),
        "target_repo": target_repo,
        "scan": scan_info,
    }

    if not raw_results_path.exists():
        normalized = {
            "schema_version": "1.1",
            "tool": "sonar",
            "tool_version": metadata.get("scanner_version"),
            "target_repo": target_repo,
            "scan": scan_info,
            "run_metadata": metadata,
            "findings": [],
        }
        write_json(normalized_path, normalized)
        return

    with raw_results_path.open(encoding="utf-8") as f:
        data = json.load(f)

    issues = data.get("issues") or []

    # --- Classification: collect unique rule_ids and query rules API ---
    rule_ids: List[str] = []
    for issue in issues:
        rid = issue.get("rule")
        if isinstance(rid, str) and rid not in rule_ids:
            rule_ids.append(rid)

    print(
        f"🔍 Normalization: {len(issues)} issues, {len(rule_ids)} unique rule_id values."
    )
    print(f"   Enriching with Sonar rules API at {sonar_host} (org={sonar_org})")

    rule_cache: Dict[str, Dict[str, Any]] = {}
    for rid in rule_ids:
        classification = fetch_rule_classification(sonar_host, sonar_org, sonar_token, rid)
        if classification:
            rule_cache[rid] = classification

    print(
        f"✅ Retrieved classification for {len(rule_cache)} / {len(rule_ids)} rules."
    )

    findings: List[Dict[str, Any]] = []
    enriched_count = 0

    for issue in issues:
        rule_id = issue.get("rule")
        severity_raw = (issue.get("severity") or "").upper()
        message = issue.get("message")
        component = issue.get("component") or ""
        line = issue.get("line")

        text_range = issue.get("textRange") or {}
        if line is None:
            line = text_range.get("startLine")
        end_line = text_range.get("endLine", line)

        # Map component (e.g. "myproj:src/main/java/Foo.java") to file path
        file_path = None
        if component:
            if ":" in component:
                file_path = component.split(":", 1)[1]
            else:
                file_path = component

        # Base severity mapping from Sonar to HIGH/MEDIUM/LOW
        if severity_raw in ("BLOCKER", "CRITICAL", "MAJOR"):
            severity = "HIGH"
        elif severity_raw == "MINOR":
            severity = "MEDIUM"
        elif severity_raw == "INFO":
            severity = "LOW"
        else:
            severity = None

        # Try to read the source line for context
        line_content = None
        if file_path and line:
            file_abs = repo_path / file_path
            try:
                lines = file_abs.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
                if 1 <= line <= len(lines):
                    line_content = lines[line - 1].rstrip("\n")
            except OSError:
                pass

        # Classification from rules API (if available)
        cwe_id: Optional[str] = None
        cwe_ids: Optional[List[str]] = None
        vuln_class: Optional[str] = None
        owasp_2017 = None
        owasp_2021 = None

        cls = rule_cache.get(rule_id)
        if cls:
            cwe_ids = cls.get("cwe_ids") or []
            if cwe_ids:
                cwe_id = cwe_ids[0]
            vuln_class = cls.get("vuln_class")
            owasp_2017 = cls.get("owasp_top_10_2017")
            owasp_2021 = cls.get("owasp_top_10_2021")
            enriched_count += 1

        finding: Dict[str, Any] = {
            "metadata": per_finding_metadata,
            "finding_id": f"sonar:{rule_id}:{file_path}:{line}",
            "cwe_id": cwe_id,
            "rule_id": rule_id,
            "title": message,
            "severity": severity,
            "file_path": file_path,
            "line_number": line,
            "end_line_number": end_line,
            "line_content": line_content,
            "vendor": {
                "raw_result": issue,
            },
        }

        # Only add these keys when we actually have something
        if cwe_ids:
            finding["cwe_ids"] = cwe_ids
        if vuln_class:
            finding["vuln_class"] = vuln_class
        if owasp_2017:
            finding["owasp_top_10_2017"] = owasp_2017
        if owasp_2021:
            finding["owasp_top_10_2021"] = owasp_2021

        findings.append(finding)

    normalized = {
        "schema_version": "1.1",
        "tool": "sonar",
        "tool_version": metadata.get("scanner_version"),
        "target_repo": target_repo,
        "scan": scan_info,
        "run_metadata": metadata,
        "sonar_rules_enrichment": {
            "source": "api/rules/show",
            "host": sonar_host,
            "organization": sonar_org,
            "rules_with_classification": len(rule_cache),
            "findings_enriched": enriched_count,
        },
        "findings": findings,
    }

    write_json(normalized_path, normalized)


# ---------------------------------------------------------------------------
# Top-level pipeline
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    # 0. Config & credentials
    cfg = get_sonar_config()
    print(f"Using Sonar host: {cfg.host}")
    print(f"Using organization: {cfg.org}")

    validate_sonarcloud_credentials(cfg.host, cfg.org, cfg.token)

    # 1. Repo preparation
    repo_path, repo_name = prepare_repo(args.repo_url)
    project_key = args.project_key or f"{cfg.org}_{repo_name}"
    print(f"Sonar project key: {project_key}")

    # 2. Run directory / file paths
    run_id, paths = prepare_run_paths(args.output_root, repo_name)

    scan_time: Optional[float] = None
    status = "skipped" if args.skip_scan else "success"
    command_str: Optional[str] = None
    exit_code: Optional[int] = None

    # 3. sonar-scanner (optional)
    if not args.skip_scan:
        returncode, elapsed, cmd = run_sonar_scan(
            repo_path=repo_path,
            project_key=project_key,
            sonar_host=cfg.host,
            sonar_org=cfg.org,
            sonar_token=cfg.token,
            java_binaries=args.java_binaries,
            log_path=paths.log,
        )
        scan_time = elapsed
        command_str = " ".join(cmd)
        exit_code = returncode

        if returncode != 0:
            print(f"⚠️ sonar-scanner failed with code {returncode}. See log: {paths.log}")
            status = "scan_failed"
        else:
            print(f"✅ sonar-scanner finished in {elapsed:.2f}s. Log: {paths.log}")
    else:
        print("⏭️ Skipping sonar-scanner run (per --skip-scan).")

    if status == "success":
        wait_for_ce_success(cfg.host, cfg.org, project_key, cfg.token)

    # 4. Fetch issues from SonarCloud
    issues = fetch_all_issues_for_project(cfg.host, project_key, cfg.org, cfg.token)
    print(f"📥 Retrieved {len(issues)} issues from SonarCloud")

    raw_payload = build_issues_payload(
        project_key=project_key,
        cfg=cfg,
        repo_name=repo_name,
        issues=issues,
        run_id=run_id,
        scan_time=scan_time,
    )
    write_json(paths.raw_results, raw_payload)
    print("📄 Issues JSON saved to:", paths.raw_results)

    # 5. Metadata JSON (per run)
    metadata = build_run_metadata(
        cfg=cfg,
        repo_path=repo_path,
        repo_name=repo_name,
        repo_url=args.repo_url,
        project_key=project_key,
        run_id=run_id,
        issues=issues,
        scan_time=scan_time,
        status=status,
        paths=paths,
        command_str=command_str,
        exit_code=exit_code,
    )
    write_json(paths.metadata, metadata)
    print("📄 Metadata saved to:", paths.metadata)

    # 6. Normalized JSON (schema v1.1 + CWE/OWASP enrichment)
    normalize_sonar_results(
        repo_path=repo_path,
        raw_results_path=paths.raw_results,
        metadata=metadata,
        normalized_path=paths.normalized,
        sonar_host=cfg.host,
        sonar_org=cfg.org,
        sonar_token=cfg.token,
    )
    print("📄 Normalized JSON saved to:", paths.normalized)


if __name__ == "__main__":
    main()
