"""tools/aikido/runner.py

Aikido scan orchestration (list repos -> select -> (optional) trigger -> export issues -> normalize).
"""

from __future__ import annotations

import os
import re
import traceback
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from dotenv import load_dotenv

from tools.core import create_run_dir_compat, write_json
from .client import AIKIDO_TOOL_VERSION, API_ROOT, get_access_token, list_code_repos, export_all_issues, trigger_aikido_scan
from .normalize import normalize_aikido_results

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = PROJECT_ROOT / ".env"

_GH_OWNER_REPO_RE = re.compile(r"(?i)\b([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)\b")


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


def prepare_run_paths(output_root: str, repo_name: str) -> Tuple[str, RunPaths]:
    run_id, run_dir = create_run_dir_compat(Path(output_root) / repo_name)
    return run_id, RunPaths(
        run_dir=run_dir,
        raw_results=run_dir / f"{repo_name}.json",
        normalized=run_dir / f"{repo_name}.normalized.json",
        metadata=run_dir / "metadata.json",
    )


def get_aikido_config() -> AikidoConfig:
    client_id = os.getenv("AIKIDO_CLIENT_ID")
    client_secret = os.getenv("AIKIDO_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise SystemExit(
            "ERROR: set AIKIDO_CLIENT_ID and AIKIDO_CLIENT_SECRET env vars "
            "(or in .env at project root)."
        )
    token = get_access_token(client_id, client_secret)
    return AikidoConfig(client_id=client_id, client_secret=client_secret, token=token)


def choose_git_ref_interactively(repos: Sequence[Dict[str, Any]]) -> str:
    print("Available Aikido code repos:")
    for idx, r in enumerate(repos, start=1):
        print(f"[{idx}] id={r.get('id')} | name={r.get('name')} | url={r.get('url')}")
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


def _slugify(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return re.sub(r"-+", "-", s).strip("-")


def _extract_owner_repo(text: str) -> Optional[Tuple[str, str]]:
    t = (text or "").strip()
    if not t:
        return None
    low = t.lower()
    if "api.github.com/repos/" in low:
        tail = low.split("api.github.com/repos/", 1)[1]
        parts = [p for p in tail.split("/") if p]
        if len(parts) >= 2:
            return parts[0], parts[1].removesuffix(".git")
    if "github.com/" in low:
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
        vars.add(url.lower().replace("https://", "").replace("http://", ""))
    owner_repo = _extract_owner_repo(url)
    if owner_repo:
        vars.add(f"{owner_repo[0]}/{owner_repo[1]}")
        vars.add(owner_repo[1])
    return vars, owner_repo


def find_repo_by_git_ref(repos: Sequence[Dict[str, Any]], git_ref: str) -> Tuple[str, Dict[str, Any]]:
    selector = (git_ref or "").strip()
    if not selector:
        raise ValueError("Empty git_ref")

    sel_low = selector.lower().strip()
    sel_slug = _slugify(selector)
    sel_owner_repo = _extract_owner_repo(selector)
    sel_repo_only = sel_owner_repo[1] if sel_owner_repo else None

    for r in repos:
        variants, _ = _repo_variants(r)
        if sel_low in variants or sel_slug in variants:
            return str(r["id"]), r
        if sel_owner_repo and f"{sel_owner_repo[0]}/{sel_owner_repo[1]}" in variants:
            return str(r["id"]), r
        if sel_repo_only and sel_repo_only in variants:
            return str(r["id"]), r

    for r in repos:
        url = str(r.get("url") or "").lower()
        if not url:
            continue
        if sel_low and sel_low in url:
            return str(r["id"]), r
        if sel_owner_repo and f"{sel_owner_repo[0]}/{sel_owner_repo[1]}" in url:
            return str(r["id"]), r
        if sel_repo_only and f"/{sel_repo_only}" in url:
            return str(r["id"]), r

    raise ValueError(
        "No Aikido repo found for %r.\n"
        "Tip: try --git-ref <owner>/<repo> (e.g. juice-shop/juice-shop) or run without --git-ref to pick from the interactive list."
        % selector
    )


def filter_issues_for_repo(issues: Sequence[Dict[str, Any]], code_repo_id: str) -> List[Dict[str, Any]]:
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


def build_run_metadata(
    *,
    repo_name: str,
    source_repo_name: Optional[str],
    repo_url: Optional[str],
    code_repo_id: str,
    repo_obj: Dict[str, Any],
    run_id: str,
    issues_count: int,
    trigger_http_seconds: Optional[float],
    command_str: str,
) -> Dict[str, Any]:
    return {
        "scanner": "aikido",
        "scanner_version": AIKIDO_TOOL_VERSION,
        "repo_name": repo_name,
        "source_repo_name": source_repo_name,
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
        "repo_commit": None,
        "commit_author_name": None,
        "commit_author_email": None,
        "commit_date": None,
    }


def execute(*, git_ref: Optional[str], output_root: str, skip_trigger: bool, repo_name_override: Optional[str] = None) -> Tuple[RunPaths, Dict[str, Any]]:
    # Load project .env (if present)
    load_dotenv(ENV_PATH)

    cfg = get_aikido_config()

    repos = list_code_repos(cfg.token)

    selected_git_ref = git_ref or choose_git_ref_interactively(repos)
    code_repo_id, repo_obj = find_repo_by_git_ref(repos, selected_git_ref)

    source_repo_name = repo_obj.get("name") or "unknown_repo"
    repo_name = repo_name_override or source_repo_name
    repo_url = repo_obj.get("url")

    run_id, paths = prepare_run_paths(output_root, repo_name)

    trigger_http_seconds: Optional[float] = None
    if not skip_trigger:
        trigger_http_seconds = trigger_aikido_scan(cfg.token, code_repo_id)

    all_issues = export_all_issues(cfg.token)
    repo_issues = filter_issues_for_repo(all_issues, code_repo_id)

    write_json(paths.raw_results, repo_issues)

    command_str = f"GET {API_ROOT}/issues/export (code_repo_id={code_repo_id})"

    metadata = build_run_metadata(
        repo_name=repo_name,
        source_repo_name=source_repo_name,
        repo_url=repo_url,
        code_repo_id=code_repo_id,
        repo_obj=repo_obj,
        run_id=run_id,
        issues_count=len(repo_issues),
        trigger_http_seconds=trigger_http_seconds,
        command_str=command_str,
    )
    write_json(paths.metadata, metadata)

    normalize_aikido_results(paths.raw_results, metadata, paths.normalized)

    return paths, metadata


def cli_entry(git_ref: Optional[str], output_root: str, skip_trigger: bool, repo_name_override: Optional[str] = None) -> None:
    try:
        paths, _meta = execute(git_ref=git_ref, output_root=output_root, skip_trigger=skip_trigger, repo_name_override=repo_name_override)
        print(f"Run complete.")
        print(f"  Issues JSON     : {paths.raw_results}")
        print(f"  Metadata        : {paths.metadata}")
        print(f"  Normalized JSON : {paths.normalized}")
    except SystemExit as e:
        if e.code not in (None, 0):
            msg = str(e)
            if msg:
                print(msg)
        raise
    except Exception as e:
        print(f"ERROR: tools.aikido failed: {e}")
        traceback.print_exc()
        raise SystemExit(1)
