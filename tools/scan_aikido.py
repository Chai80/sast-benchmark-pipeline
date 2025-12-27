#!/usr/bin/env python3
"""tools/scan_aikido.py

Aikido pipeline script for the sast-benchmark-pipeline.

Given an Aikido-connected code repository, this script:
  * authenticates against the Aikido Public API
  * optionally triggers a scan for the chosen code repo
  * exports issues via /issues/export and filters them to that repo
  * writes:
        runs/aikido/<repo_name>/<run_id>/<repo_name>.json             (raw issues list)
        runs/aikido/<repo_name>/<run_id>/<repo_name>.normalized.json  (normalized findings)
        runs/aikido/<repo_name>/<run_id>/metadata.json                (run metadata)

Notes on timings:
  * For Aikido, we do not see internal engine time.
  * We measure HTTP latency for the /scan trigger call as trigger_http_seconds.
  * In metadata, scan_time_seconds is set equal to trigger_http_seconds so the
    runtime benchmark can compare this field across tools (with this caveat).

Requirements:
  * AIKIDO_CLIENT_ID and AIKIDO_CLIENT_SECRET set in .env at project root
    or in the environment.

Normalization:
  * Emits schema_version 1.1
  * Uses tools/classification_resolver.py to populate:
      - cwe_id / cwe_ids
      - owasp_top_10_2017
      - owasp_top_10_2021
    derived from:
      - explicit CWE/OWASP fields in the Aikido issue payload (when present)
      - tags/text fields
      - CWE->OWASP MITRE mapping (mappings/cwe_to_owasp_top10_mitre.json)
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import traceback
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests
from dotenv import load_dotenv



# ---------------------------------------------------------------------------
# Package bootstrap + imports
# ---------------------------------------------------------------------------

# When this file is executed directly (e.g. `python tools/scan_aikido.py`),
# Python adds `tools/` (not the project root) to sys.path, so `import tools.*`
# would fail. This keeps both invocation styles working:
#   - python -m tools.scan_aikido
#   - python tools/scan_aikido.py
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))

from tools.core import create_run_dir_compat, load_cwe_to_owasp_map, write_json
from tools.normalize_common import (
    build_per_finding_metadata,
    build_scan_info,
    build_target_repo,
)
from tools.classification_resolver import resolve_owasp_and_cwe

TOKEN_URL = "https://app.aikido.dev/api/oauth/token"
API_ROOT = "https://app.aikido.dev/api/public/v1"
AIKIDO_TOOL_VERSION = "public-api-v1"

# Path to optional project-local .env file (loaded inside main()).
ENV_PATH = PROJECT_ROOT / ".env"



# ---------------------------------------------------------------------------
# Data structs
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AikidoConfig:
    client_id: str
    client_secret: str
    token: str


@dataclass(frozen=True)
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
        description="Run Aikido scan and export issues for a connected repo."
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
        help="Output root folder (default: runs/aikido)",
    )
    parser.add_argument(
        "--skip-trigger",
        action="store_true",
        help="Skip triggering a scan; export the latest existing issues.",
    )
    return parser.parse_args()


def get_aikido_config() -> AikidoConfig:
    """Read Aikido credentials from env and obtain an access token."""
    client_id = os.getenv("AIKIDO_CLIENT_ID")
    client_secret = os.getenv("AIKIDO_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise SystemExit(
            "ERROR: set AIKIDO_CLIENT_ID and AIKIDO_CLIENT_SECRET env vars "
            "(or in .env at project root)."
        )

    token = get_access_token(client_id, client_secret)
    return AikidoConfig(client_id=client_id, client_secret=client_secret, token=token)


def prepare_run_paths(output_root: str, repo_name: str) -> Tuple[str, RunPaths]:
    """Create a new run directory and compute output paths."""
    run_id, run_dir = create_run_dir_compat(Path(output_root) / repo_name)

    raw_path = run_dir / f"{repo_name}.json"
    normalized_path = run_dir / f"{repo_name}.normalized.json"
    metadata_path = run_dir / "metadata.json"

    return run_id, RunPaths(
        run_dir=run_dir,
        raw_results=raw_path,
        normalized=normalized_path,
        metadata=metadata_path,
    )


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
    payload = resp.json()
    return payload["access_token"]


def list_code_repos(token: str) -> List[Dict[str, Any]]:
    """Return all Aikido code repos for this workspace."""
    url = f"{API_ROOT}/repositories/code"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data["data"] if isinstance(data, dict) and "data" in data else data


def choose_git_ref_interactively(repos: Sequence[Dict[str, Any]]) -> str:
    """Show a numbered menu [1..N] and return the chosen repo's git_ref."""
    print("Available Aikido code repos:")
    for idx, r in enumerate(repos, start=1):
        print(
            f"[{idx}] id={r.get('id')} | "
            f"name={r.get('name')} | "
            f"url={r.get('url')}"
        )

    while True:
        choice = input(f"Enter the number of the repo to scan (1-{len(repos)}): ").strip()
        try:
            n = int(choice)
            if 1 <= n <= len(repos):
                selected = repos[n - 1]
                git_ref = selected.get("name") or selected.get("url")
                print(f"Selected repo: {git_ref}")
                return str(git_ref)
        except ValueError:
            pass
        print("Invalid choice, please try again.")


_GH_OWNER_REPO_RE = re.compile(r"(?i)\b([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)\b")


def _slugify(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return re.sub(r"-+", "-", s).strip("-")


def _extract_owner_repo(text: str) -> Optional[Tuple[str, str]]:
    """Extract (owner, repo) from GitHub URL or owner/repo string."""
    t = (text or "").strip()
    if not t:
        return None
    low = t.lower()
    if "api.github.com/repos/" in low:
        # https://api.github.com/repos/owner/repo
        tail = low.split("api.github.com/repos/", 1)[1]
        parts = [p for p in tail.split("/") if p]
        if len(parts) >= 2:
            return parts[0], parts[1].removesuffix(".git")
    if "github.com/" in low:
        # https://github.com/owner/repo(.git)
        tail = low.split("github.com/", 1)[1]
        parts = [p for p in tail.split("/") if p]
        if len(parts) >= 2:
            return parts[0], parts[1].removesuffix(".git")

    m = _GH_OWNER_REPO_RE.search(low)
    if m:
        return m.group(1), m.group(2).removesuffix(".git")
    return None


def _repo_variants(repo_obj: Dict[str, Any]) -> Tuple[set[str], Optional[Tuple[str, str]]]:
    name = str(repo_obj.get("name") or "").strip()
    url = str(repo_obj.get("url") or "").strip()

    vars: set[str] = set()
    if name:
        vars.add(name.lower())
        vars.add(_slugify(name))
    if url:
        vars.add(url.lower())
        # also keep a normalized (no scheme) variant for substring checks
        vars.add(url.lower().replace("https://", "").replace("http://", ""))

    owner_repo = _extract_owner_repo(url)
    if owner_repo:
        vars.add(f"{owner_repo[0]}/{owner_repo[1]}")
        vars.add(owner_repo[1])
    return vars, owner_repo


def find_repo_by_git_ref(repos: Sequence[Dict[str, Any]], git_ref: str) -> Tuple[str, Dict[str, Any]]:
    """Find an Aikido repo by a flexible selector.

    Accepts:
      - repo display name ("Juice Shop")
      - repo slug/name ("juice-shop")
      - owner/repo ("juice-shop/juice-shop")
      - GitHub URL ("https://github.com/juice-shop/juice-shop")
      - GitHub API URL ("https://api.github.com/repos/juice-shop/juice-shop")
    """
    selector = (git_ref or "").strip()
    if not selector:
        raise ValueError("Empty git_ref")

    sel_low = selector.lower().strip()
    sel_slug = _slugify(selector)
    sel_owner_repo = _extract_owner_repo(selector)
    sel_repo_only = sel_owner_repo[1] if sel_owner_repo else None

    # Try exact-ish matches first
    for r in repos:
        variants, _ = _repo_variants(r)
        if sel_low in variants or sel_slug in variants:
            return str(r["id"]), r
        if sel_owner_repo and f"{sel_owner_repo[0]}/{sel_owner_repo[1]}" in variants:
            return str(r["id"]), r
        if sel_repo_only and sel_repo_only in variants:
            return str(r["id"]), r

    # Then substring matches against repo URLs
    for r in repos:
        url = str(r.get("url") or "").lower()
        if not url:
            continue
        if sel_low and sel_low in url:
            return str(r["id"]), r
        if sel_owner_repo:
            if f"{sel_owner_repo[0]}/{sel_owner_repo[1]}" in url:
                return str(r["id"]), r
        if sel_repo_only and f"/{sel_repo_only}" in url:
            return str(r["id"]), r

    raise ValueError(
        "No Aikido repo found for %r.\n"
        "Tip: try --git-ref <owner>/<repo> (e.g. juice-shop/juice-shop) or run without --git-ref to pick from the interactive list."
        % selector
    )


def export_all_issues(token: str) -> List[Dict[str, Any]]:
    """Export all issues from Aikido."""
    url = f"{API_ROOT}/issues/export"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    return data["data"] if isinstance(data, dict) and "data" in data else data


def filter_issues_for_repo(issues: Sequence[Dict[str, Any]], code_repo_id: str) -> List[Dict[str, Any]]:
    """Return only issues belonging to the given Aikido code_repo_id.

    Aikido's export payload has shown small schema drift over time, so we check a
    couple common locations.
    """
    want = str(code_repo_id)

    def _get_issue_repo_id(issue: Dict[str, Any]) -> Optional[str]:
        for k in ("code_repo_id", "codeRepoId", "repository_id", "repo_id"):
            v = issue.get(k)
            if v is not None:
                return str(v)

        for k in ("repository", "code_repo", "codeRepo", "codeRepository"):
            v = issue.get(k)
            if isinstance(v, dict) and v.get("id") is not None:
                return str(v.get("id"))
        return None

    out: List[Dict[str, Any]] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        rid = _get_issue_repo_id(issue)
        if rid == want:
            out.append(issue)
    return out


def trigger_aikido_scan(token: str, code_repo_id: str) -> Optional[float]:
    """Trigger an Aikido scan for the given repo. Returns HTTP latency seconds."""
    headers = {"Authorization": f"Bearer {token}"}
    scan_url = f"{API_ROOT}/repositories/code/{code_repo_id}/scan"

    try:
        t0 = time.time()
        resp = requests.post(scan_url, headers=headers, timeout=30)
        if resp.status_code == 403:
            print("No permission to trigger scan; using latest existing results.")
            return None
        resp.raise_for_status()
        return time.time() - t0
    except Exception as e:
        print(f"Warning: scan trigger failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Normalization: Aikido issues -> schema v1.1
# ---------------------------------------------------------------------------

def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _coerce_int(x: Any) -> Optional[int]:
    try:
        if x is None:
            return None
        if isinstance(x, bool):
            return None
        return int(x)
    except Exception:
        return None


def _map_severity(issue: Dict[str, Any]) -> Optional[str]:
    raw = (issue.get("severity") or issue.get("risk") or issue.get("level") or "")
    s = str(raw).strip().upper()
    if s in {"CRITICAL", "HIGH"}:
        return "HIGH"
    if s in {"MEDIUM", "MODERATE"}:
        return "MEDIUM"
    if s in {"LOW", "INFO", "INFORMATIONAL"}:
        return "LOW"
    return None


def _extract_rule_id(issue: Dict[str, Any]) -> Optional[str]:
    for k in ("rule_id", "rule", "type", "category"):
        v = issue.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
        if v is not None and not isinstance(v, (dict, list)):
            return str(v)
    return None


def _extract_title(issue: Dict[str, Any], issue_id: Any) -> Optional[str]:
    for k in ("title", "summary", "message", "name"):
        v = issue.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    if issue_id is not None:
        return f"Aikido issue {issue_id}"
    return None


def _extract_location(issue: Dict[str, Any]) -> Tuple[Optional[str], Optional[int], Optional[int]]:
    """Best-effort extraction of file + (start,end) line."""
    file_path = (
        issue.get("file_path")
        or issue.get("file")
        or issue.get("path")
        or issue.get("affected_file")
        or issue.get("affectedFile")
    )
    line = issue.get("line") or issue.get("line_number") or issue.get("start_line")
    end_line = issue.get("end_line") or issue.get("end_line_number") or issue.get("endLine")

    loc = issue.get("location") or issue.get("source_location")
    if isinstance(loc, dict):
        file_path = (
            file_path
            or loc.get("file_path")
            or loc.get("file")
            or loc.get("path")
            or loc.get("affected_file")
            or loc.get("affectedFile")
        )
        line = line or loc.get("line") or loc.get("line_number") or loc.get("start_line")
        end_line = end_line or loc.get("end_line") or loc.get("end_line_number")

    line_i = _coerce_int(line)
    end_i = _coerce_int(end_line) or line_i

    return (str(file_path) if file_path else None, line_i, end_i)


def _extract_vendor_owasp_2021_codes(issue: Dict[str, Any]) -> List[str]:
    """Extract explicit OWASP 2021 codes if Aikido provides them."""
    candidates: List[Any] = []

    for k in (
        "owasp_top_10_2021",
        "owasp_2021",
        "owasp2021",
        "owaspTop10_2021",
    ):
        candidates.extend(_as_list(issue.get(k)))

    owasp = issue.get("owasp")
    if isinstance(owasp, dict):
        candidates.extend(_as_list(owasp.get("2021")))
        candidates.extend(_as_list(owasp.get("owasp_top_10_2021")))
        candidates.extend(_as_list(owasp.get("top_10_2021")))

    flattened: List[str] = []
    for v in candidates:
        if v is None:
            continue
        if isinstance(v, dict):
            codes = v.get("codes") or v.get("code") or v.get("owasp")
            for c in _as_list(codes):
                if c is not None:
                    flattened.append(str(c))
        else:
            flattened.append(str(v))

    return [s for s in flattened if s.strip()]


def _extract_cwe_candidates(issue: Dict[str, Any]) -> List[Any]:
    cands: List[Any] = []
    for k in (
        "cwe",
        "cwe_id",
        "cwe_ids",
        "cwe_classes",
        "cweClasses",
        "cweIds",
        "cweId",
        "cweID",
    ):
        cands.extend(_as_list(issue.get(k)))

    weakness = issue.get("weakness") or issue.get("weaknesses")
    if isinstance(weakness, dict):
        cands.extend(_as_list(weakness.get("cwe")))
        cands.extend(_as_list(weakness.get("cwe_id")))
        cands.extend(_as_list(weakness.get("cwe_ids")))
    elif isinstance(weakness, list):
        for w in weakness:
            if isinstance(w, dict):
                cands.extend(_as_list(w.get("cwe")))
                cands.extend(_as_list(w.get("cwe_id")))
                cands.extend(_as_list(w.get("cwe_ids")))

    return cands


def _collect_tags(issue: Dict[str, Any]) -> List[str]:
    """Collect a broad set of textual fields to help classification extraction."""
    tags: List[str] = []

    for k in ("tags", "labels", "categories", "category", "type", "subtype", "language", "rule", "rule_id"):
        for v in _as_list(issue.get(k)):
            if v is None or isinstance(v, (dict, list)):
                continue
            s = str(v).strip()
            if s:
                tags.append(s)

    for k in ("title", "summary", "message", "description"):
        v = issue.get(k)
        if isinstance(v, str) and v.strip():
            tags.append(v.strip())

    for v in _as_list(issue.get("owasp")):
        if isinstance(v, str) and v.strip():
            tags.append(v.strip())

    return tags


def _build_finding(
    *,
    issue: Dict[str, Any],
    per_finding_metadata: Dict[str, Any],
    cwe_to_owasp_map: Dict[str, Any],
) -> Dict[str, Any]:
    issue_id = issue.get("id")
    rule_id = _extract_rule_id(issue)
    title = _extract_title(issue, issue_id)
    severity = _map_severity(issue)
    file_path, line, end_line = _extract_location(issue)

    tags = _collect_tags(issue)
    cwe_candidates = _extract_cwe_candidates(issue)
    vendor_owasp_2021 = _extract_vendor_owasp_2021_codes(issue)

    classification = resolve_owasp_and_cwe(
        tags=tags,
        cwe_candidates=cwe_candidates,
        cwe_to_owasp_map=cwe_to_owasp_map,
        vendor_owasp_2021_codes=vendor_owasp_2021 or None,
        allow_2017_from_tags=True,
    )

    stable_parts = [
        str(issue_id) if issue_id is not None else None,
        rule_id,
        file_path,
        str(line) if line is not None else None,
    ]
    stable = ":".join([p for p in stable_parts if p]) or "unknown"

    return {
        "metadata": per_finding_metadata,
        "finding_id": f"aikido:{stable}",
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "file_path": file_path,
        "line_number": line,
        "end_line_number": end_line,
        "line_content": None,  # no local source checkout in Aikido API mode

        # mappings/classification
        "cwe_id": classification.get("cwe_id"),
        "cwe_ids": classification.get("cwe_ids") or [],
        "owasp_top_10_2017": classification.get("owasp_top_10_2017"),
        "owasp_top_10_2021": classification.get("owasp_top_10_2021"),

        "vendor": {"raw_result": issue},
    }


def normalize_aikido_results(
    raw_results_path: Path,
    metadata: Dict[str, Any],
    normalized_path: Path,
) -> None:
    """Convert Aikido issues JSON into the common normalized schema (v1.1)."""
    target_repo = build_target_repo(metadata)
    scan_info = build_scan_info(metadata, raw_results_path)
    per_finding_metadata = build_per_finding_metadata(
        tool="aikido",
        tool_version=metadata.get("scanner_version"),
        target_repo=target_repo,
        scan_info=scan_info,
    )

    if not raw_results_path.exists():
        write_json(
            normalized_path,
            {
                "schema_version": "1.1",
                "tool": "aikido",
                "tool_version": metadata.get("scanner_version"),
                "target_repo": target_repo,
                "scan": scan_info,
                "run_metadata": metadata,
                "findings": [],
            },
        )
        return

    issues_raw = json.loads(raw_results_path.read_text(encoding="utf-8"))

    if isinstance(issues_raw, list):
        issues: List[Dict[str, Any]] = [x for x in issues_raw if isinstance(x, dict)]
    elif isinstance(issues_raw, dict) and isinstance(issues_raw.get("data"), list):
        issues = [x for x in issues_raw["data"] if isinstance(x, dict)]
    else:
        issues = []

    cwe_to_owasp_map = load_cwe_to_owasp_map()

    findings: List[Dict[str, Any]] = []
    for issue in issues:
        try:
            findings.append(
                _build_finding(
                    issue=issue,
                    per_finding_metadata=per_finding_metadata,
                    cwe_to_owasp_map=cwe_to_owasp_map,
                )
            )
        except Exception as e:
            findings.append(
                {
                    "metadata": per_finding_metadata,
                    "finding_id": f"aikido:parse_error:{issue.get('id')}",
                    "rule_id": _extract_rule_id(issue),
                    "title": _extract_title(issue, issue.get("id")) or "Aikido issue (parse_error)",
                    "severity": _map_severity(issue),
                    "file_path": (
                        issue.get("file_path")
                        or issue.get("file")
                        or issue.get("path")
                        or issue.get("affected_file")
                        or issue.get("affectedFile")
                    ),
                    "line_number": _coerce_int(issue.get("line") or issue.get("line_number")),
                    "end_line_number": _coerce_int(issue.get("end_line") or issue.get("end_line_number")),
                    "line_content": None,
                    "cwe_id": None,
                    "cwe_ids": [],
                    "owasp_top_10_2017": None,
                    "owasp_top_10_2021": None,
                    "vendor": {"raw_result": issue, "parse_error": str(e)},
                }
            )

    write_json(
        normalized_path,
        {
            "schema_version": "1.1",
            "tool": "aikido",
            "tool_version": metadata.get("scanner_version"),
            "target_repo": target_repo,
            "scan": scan_info,
            "run_metadata": metadata,
            "findings": findings,
        },
    )


# ---------------------------------------------------------------------------
# Metadata builder
# ---------------------------------------------------------------------------

def build_run_metadata(
    *,
    repo_name: str,
    repo_url: Optional[str],
    code_repo_id: str,
    repo_obj: Dict[str, Any],
    run_id: str,
    issues_count: int,
    trigger_http_seconds: Optional[float],
    command_str: str,
) -> Dict[str, Any]:
    """Build metadata.json for an Aikido run."""
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
        "trigger_http_seconds": float(trigger_http_seconds) if trigger_http_seconds is not None else None,
        "scan_time_seconds": float(trigger_http_seconds) if trigger_http_seconds is not None else None,
        "command": command_str,
        "exit_code": 0,
        # Aikido public API does not give us commit/author metadata.
        "repo_commit": None,
        "commit_author_name": None,
        "commit_author_email": None,
        "commit_date": None,
    }


# ---------------------------------------------------------------------------
# Top-level pipeline
# ---------------------------------------------------------------------------

def main() -> None:
    # Load project .env (if present) so credentials can be provided via file.
    load_dotenv(ENV_PATH)
    args = parse_args()
    cfg = get_aikido_config()

    # 1) Discover repos from Aikido
    repos = list_code_repos(cfg.token)

    # 2) Choose repo (CLI arg or interactive)
    git_ref = args.git_ref or choose_git_ref_interactively(repos)
    code_repo_id, repo_obj = find_repo_by_git_ref(repos, git_ref)

    repo_name = repo_obj.get("name") or "unknown_repo"
    repo_url = repo_obj.get("url")

    # 3) Prepare run directory / paths
    run_id, paths = prepare_run_paths(args.output_root, repo_name)

    # 4) Trigger scan (best effort)
    trigger_http_seconds: Optional[float] = None
    if not args.skip_trigger:
        trigger_http_seconds = trigger_aikido_scan(cfg.token, code_repo_id)

    # 5) Export issues and filter for chosen repo
    all_issues = export_all_issues(cfg.token)
    repo_issues = filter_issues_for_repo(all_issues, code_repo_id)

    write_json(paths.raw_results, repo_issues)

    # Command string for normalized schema: describe the API call we used
    command_str = f"GET {API_ROOT}/issues/export (code_repo_id={code_repo_id})"

    # 6) Build and save metadata
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
    print(f"  Issues JSON     : {paths.raw_results}")
    print(f"  Metadata        : {paths.metadata}")

    # 7) Normalized JSON
    normalize_aikido_results(paths.raw_results, metadata, paths.normalized)
    print(f"  Normalized JSON : {paths.normalized}")




def _mirror_error(msg: str) -> None:
    """Print to stderr + stdout (some wrappers only capture stdout)."""
    print(msg, file=sys.stderr)
    print(msg)


def cli_entry() -> None:
    """CLI entrypoint."""
    try:
        main()
    except SystemExit as e:
        # Mirror non-zero exit reasons to stdout as well.
        if e.code not in (None, 0):
            msg = str(e)
            if msg:
                _mirror_error(msg)
        raise
    except Exception as e:
        _mirror_error(f"ERROR: tools.scan_aikido failed: {e}")
        traceback.print_exc()
        raise SystemExit(1)


if __name__ == "__main__":
    cli_entry()
