"""tools/aikido/runner.py

Aikido scan orchestration.

We support two backends:

* **cloud**: use Aikido Public API to trigger a scan for a connected repo and export
  the currently stored issues.

* **local**: run the Aikido *Local Scanner* (recommended for the Durinn micro‑suite).
  This is the only reliable way to get branch-accurate results for a branch-per-case
  suite, because Aikido's cloud integration stores issues primarily for a configured
  "scanned branch" unless multi-branch scanning is enabled.

The stable entrypoint remains :mod:`tools/scan_aikido.py`.
"""

from __future__ import annotations

import os
import re
import shutil
import traceback
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from dotenv import load_dotenv

from tools.core import (
    acquire_repo,
    build_run_metadata as build_std_run_metadata,
    create_run_dir_compat,
    run_cmd,
    which_or_raise,
    write_json,
)
from .client import AIKIDO_TOOL_VERSION, API_ROOT, get_access_token, list_code_repos, export_all_issues, trigger_aikido_scan
from .normalize import normalize_aikido_results

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = PROJECT_ROOT / ".env"

def _infer_aikido_cache_dir(output_root: str) -> Path:
    """Infer a shared cache dir for Aikido API calls.

    In the human-first suite layout, each case invokes scan_aikido.py in a separate
    process. Without caching, cloud mode repeatedly calls expensive endpoints like
    /issues/export, which can trigger 429 rate limits.

    If output_root looks like:
      .../runs/suites/<suite_id>/cases/<case>/scans/aikido

    use:
      .../runs/suites/<suite_id>/.cache/aikido
    """
    p = Path(output_root).resolve()
    try:
        if p.name == "aikido" and p.parent.name in {"scans", "tool_runs"} and p.parents[2].name == "cases":
            suite_dir = p.parents[3]
            return suite_dir / ".cache" / "aikido"
    except Exception:
        pass
    return p / ".cache" / "aikido"


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


LOCAL_SCANNER_DOCKER_IMAGE_DEFAULT = "aikidosecurity/local-scanner:latest"


def prepare_run_paths(output_root: str, repo_name: str) -> Tuple[str, RunPaths]:
    """Prepare per-run output paths.

    Layouts supported:
    - v2 (suite/case): <output_root>/<run_id>/{raw.json,normalized.json,metadata.json}
      where output_root is cases/<case>/tool_runs/<tool>
    - v1 (legacy):     <output_root>/<repo_name>/<run_id>/{<repo>.json,<repo>.normalized.json,metadata.json}
    """
    out_root = Path(output_root)
    suite_mode = out_root.parent.name in {"tool_runs", "scans"}

    if suite_mode:
        run_id, run_dir = create_run_dir_compat(out_root)
        raw = run_dir / "raw.json"
        norm = run_dir / "normalized.json"
    else:
        run_id, run_dir = create_run_dir_compat(out_root / repo_name)
        raw = run_dir / f"{repo_name}.json"
        norm = run_dir / f"{repo_name}.normalized.json"

    return run_id, RunPaths(
        run_dir=run_dir,
        raw_results=raw,
        normalized=norm,
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


def _repo_branch(repo_obj: Dict[str, Any]) -> Optional[str]:
    """Best-effort extraction of the branch name for a code repo."""
    for k in ("branch", "branch_name", "scanned_branch", "scan_branch", "default_branch"):
        v = repo_obj.get(k)
        if v not in (None, ""):
            return str(v)
    return None


def find_repo_by_git_ref(
    code_repos: List[Dict[str, Any]],
    git_ref: str,
    branch: Optional[str] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Pick the correct code-repo object from Aikido's /repositories/code list.

    When multi-branch scanning is enabled, Aikido returns one 'code repo' per
    branch. In that case you should pass `branch` to avoid exporting the wrong
    branch's findings.
    """

    selector = git_ref or ""
    sel_low = selector.lower().strip()

    # Normalize GitHub URL -> owner/repo
    sel_slug = sel_low
    if sel_low.startswith("https://"):
        sel_slug = sel_low.replace("https://github.com/", "").rstrip("/")
    if sel_low.startswith("http://"):
        sel_slug = sel_low.replace("http://github.com/", "").rstrip("/")

    sel_owner_repo = sel_slug if "/" in sel_slug else ""
    sel_repo_only = sel_slug.split("/")[-1] if sel_slug else ""

    matches: List[Dict[str, Any]] = []
    for r in code_repos:
        variants, _ = _repo_variants(r)
        url = str(r.get("url") or "").lower()

        if (
            (sel_low and sel_low in variants)
            or (sel_slug and sel_slug in variants)
            or (sel_owner_repo and sel_owner_repo in variants)
            or (sel_repo_only and sel_repo_only in variants)
            or (sel_low and sel_low in url)
            or (sel_slug and sel_slug in url)
            or (sel_owner_repo and sel_owner_repo in url)
            or (sel_repo_only and f"/{sel_repo_only}" in url)
        ):
            matches.append(r)

    if not matches:
        raise ValueError(
            f"No Aikido code repo found for git-ref '{selector}'.\n"
            "Tip: use --git-ref <owner>/<repo> or a full GitHub URL, and make sure the repo is connected in Aikido."
        )

    if branch:
        branch_matches = [r for r in matches if _repo_branch(r) == branch]
        if not branch_matches:
            available = sorted({b for b in (_repo_branch(r) for r in matches) if b})
            raise ValueError(
                f"Found {len(matches)} Aikido repos matching '{selector}', but none with branch '{branch}'.\n"
                f"Available branches for this repo in Aikido: {available}"
            )
        matches = branch_matches

    # Be deterministic (API order is not guaranteed)
    def _rid(r: Dict[str, Any]) -> int:
        try:
            return int(r.get("id") or 0)
        except Exception:
            return 0

    matches = sorted(matches, key=_rid)
    chosen = matches[0]
    return int(chosen["id"]), chosen



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


def build_cloud_run_metadata(
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
        "repo_commit": None,
        "commit_author_name": None,
        "commit_author_email": None,
        "commit_date": None,
    }


def execute_cloud(*, git_ref: Optional[str], output_root: str, skip_trigger: bool, repositoryname: Optional[str] = None, branch: Optional[str] = None) -> Tuple[RunPaths, Dict[str, Any]]:
    # Load project .env (if present)
    load_dotenv(ENV_PATH)

    cfg = get_aikido_config()
    cache_dir = _infer_aikido_cache_dir(output_root)
    cache_ttl = int(os.environ.get('AIKIDO_CACHE_TTL_SECS', '3600'))
    repos = list_code_repos(cfg.token, cache_dir=str(cache_dir), cache_ttl_seconds=cache_ttl)
    selected_git_ref = git_ref or choose_git_ref_interactively(repos)
    code_repo_id, repo_obj = find_repo_by_git_ref(repos, selected_git_ref, branch=branch)

    derived_repo_name = repo_obj.get("name") or "unknown_repo"
    repo_name = repositoryname or derived_repo_name
    repo_url = repo_obj.get("url")

    run_id, paths = prepare_run_paths(output_root, repo_name)

    trigger_http_seconds: Optional[float] = None
    if not skip_trigger:
        trigger_http_seconds = trigger_aikido_scan(cfg.token, code_repo_id)

    all_issues = export_all_issues(cfg.token, cache_dir=str(cache_dir), cache_ttl_seconds=cache_ttl)
    repo_issues = filter_issues_for_repo(all_issues, code_repo_id)

    write_json(paths.raw_results, repo_issues)

    command_str = f"GET {API_ROOT}/issues/export (code_repo_id={code_repo_id})"

    metadata = build_cloud_run_metadata(
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

    normalize_aikido_results(paths.raw_results, metadata, paths.normalized)

    return paths, metadata


def _detect_git_branch(repo_path: Path) -> Optional[str]:
    """Return the current branch name, or None if unavailable/detached."""
    try:
        res = run_cmd(["git", "-C", str(repo_path), "rev-parse", "--abbrev-ref", "HEAD"], print_stdout=False, print_stderr=False)
        b = (res.stdout or "").strip()
        if not b or b == "HEAD":
            return None
        return b
    except Exception:
        return None


def _derive_repositoryname(*, git_ref: Optional[str], repo_url: Optional[str], repo_path: Path) -> str:
    """Best-effort repo name for Aikido Local Scanner's --repositoryname."""

    # Prefer the explicit (owner/repo) ref if provided.
    for candidate in (git_ref, repo_url):
        owner_repo = _extract_owner_repo(candidate or "")
        if owner_repo:
            return owner_repo[1]

    # Fall back to local folder name.
    return repo_path.name


def _require_aikido_api_key() -> None:
    if not os.environ.get("AIKIDO_API_KEY"):
        raise SystemExit(
            "Missing AIKIDO_API_KEY environment variable.\n"
            "This is required for Aikido Local Scanner.\n"
            "Get a token from Aikido: Settings → Local Scanner setup page,\n"
            "then export it as AIKIDO_API_KEY or put it in the project .env."
        )


def _run_local_scanner_docker(
    *,
    repo_path: Path,
    run_dir: Path,
    docker_image: str,
    repositoryname: str,
    branchname: str,
    scan_types: Optional[List[str]],
    fail_on: str,
    gating_mode: str,
    base_commit_id: Optional[str],
    head_commit_id: Optional[str],
    gating_output_inside: str,
    force_create_repository_for_branch: bool,
    no_snippets: bool,
    debug: bool,
) -> Tuple[int, float, str, str, str]:
    """Run local scanner via Docker and return (exit, elapsed, cmd_str, stdout, stderr)."""

    docker_bin = which_or_raise("docker")

    cmd: List[str] = [
        docker_bin,
        "run",
        "--rm",
        "-v",
        f"{repo_path}:/repo",
        "-v",
        f"{run_dir}:/out",
        "-e",
        "AIKIDO_API_KEY",
        docker_image,
        "scan",
        "/repo",
        "--repositoryname",
        repositoryname,
        "--branchname",
        branchname,
        "--tmpdirectory",
        "/tmp/aikidotmp",
        "--fail-on",
        fail_on,
        "--gating-mode",
        gating_mode,
        "--gating-result-output",
        gating_output_inside,
    ]

    if scan_types:
        cmd.append("--scan-types")
        cmd.extend(scan_types)

    if gating_mode == "pr":
        if not head_commit_id:
            raise SystemExit("Aikido local scanner PR gating mode requires --head-commit-id.")
        cmd.extend(["--head-commit-id", head_commit_id])
        if base_commit_id:
            cmd.extend(["--base-commit-id", base_commit_id])

    if force_create_repository_for_branch:
        cmd.append("--force-create-repository-for-branch")

    if no_snippets:
        cmd.append("--no-snippets")

    if debug:
        cmd.append("--debug")

    res = run_cmd(cmd, cwd=None, print_stdout=False, print_stderr=False)
    return res.exit_code, res.elapsed_seconds, res.command_str, (res.stdout or ""), (res.stderr or "")


def _run_local_scanner_binary(
    *,
    scanner_bin: str,
    repo_path: Path,
    repositoryname: str,
    branchname: str,
    scan_types: Optional[List[str]],
    fail_on: str,
    gating_mode: str,
    base_commit_id: Optional[str],
    head_commit_id: Optional[str],
    gating_output_host: Path,
    force_create_repository_for_branch: bool,
    no_snippets: bool,
    debug: bool,
) -> Tuple[int, float, str, str, str]:
    """Run local scanner via installed binary."""

    # Use a per-run tmp directory under the run output folder (never write into the repo).
    tmp_dir = gating_output_host.parent / ".tmp" / "aikido"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    cmd: List[str] = [
        scanner_bin,
        "scan",
        str(repo_path),
        "--repositoryname",
        repositoryname,
        "--branchname",
        branchname,
        "--tmpdirectory",
        str(tmp_dir),
        "--fail-on",
        fail_on,
        "--gating-mode",
        gating_mode,
        "--gating-result-output",
        str(gating_output_host),
    ]

    if scan_types:
        cmd.append("--scan-types")
        cmd.extend(scan_types)

    if gating_mode == "pr":
        if not head_commit_id:
            raise SystemExit("Aikido local scanner PR gating mode requires --head-commit-id.")
        cmd.extend(["--head-commit-id", head_commit_id])
        if base_commit_id:
            cmd.extend(["--base-commit-id", base_commit_id])

    if force_create_repository_for_branch:
        cmd.append("--force-create-repository-for-branch")

    if no_snippets:
        cmd.append("--no-snippets")

    if debug:
        cmd.append("--debug")

    res = run_cmd(cmd, cwd=None, print_stdout=False, print_stderr=False)
    return res.exit_code, res.elapsed_seconds, res.command_str, (res.stdout or ""), (res.stderr or "")


def execute_local(
    *,
    repo_path: str,
    output_root: str,
    repo_url: Optional[str] = None,
    git_ref: Optional[str] = None,
    repositoryname: Optional[str] = None,
    branch: Optional[str] = None,
    branchname: Optional[str] = None,
    scan_types: Optional[List[str]] = None,
    fail_on: str = "low",
    gating_mode: str = "release",
    base_commit_id: Optional[str] = None,
    head_commit_id: Optional[str] = None,
    force_create_repository_for_branch: bool = False,
    no_snippets: bool = False,
    debug: bool = False,
    prefer_binary: bool = False,
    docker_image: Optional[str] = None,
) -> Tuple[RunPaths, Dict[str, Any]]:
    """Run Aikido Local Scanner on a local checkout and normalize gating output."""

    # Load project .env (if present)
    load_dotenv(ENV_PATH)

    _require_aikido_api_key()

    repo = acquire_repo(repo_url=repo_url, repo_path=repo_path, repos_dir="repos")

    run_id, paths = prepare_run_paths(output_root, repo.repo_name)

    branch = branchname or _detect_git_branch(repo.repo_path) or "unknown"
    repo_name_for_aikido = repositoryname or _derive_repositoryname(git_ref=git_ref, repo_url=repo_url, repo_path=repo.repo_path)

    # Prefer the installed binary if requested and available.
    local_bin = shutil.which("aikido-local-scanner") if prefer_binary else None
    docker_image = docker_image or os.environ.get("AIKIDO_LOCAL_SCANNER_IMAGE") or LOCAL_SCANNER_DOCKER_IMAGE_DEFAULT

    stdout = ""
    stderr = ""
    if local_bin:
        exit_code, elapsed, command_str, stdout, stderr = _run_local_scanner_binary(
            scanner_bin=local_bin,
            repo_path=repo.repo_path,
            repositoryname=repo_name_for_aikido,
            branchname=branch,
            scan_types=scan_types,
            fail_on=fail_on,
            gating_mode=gating_mode,
            base_commit_id=base_commit_id,
            head_commit_id=head_commit_id or repo.commit,
            gating_output_host=paths.raw_results,
            force_create_repository_for_branch=force_create_repository_for_branch,
            no_snippets=no_snippets,
            debug=debug,
        )
    else:
        # Docker image entrypoint is `aikido-local-scanner`, so the first arg is the subcommand (e.g. `scan`).
        gating_output_inside = f"/out/{paths.raw_results.name}"
        exit_code, elapsed, command_str, stdout, stderr = _run_local_scanner_docker(
            repo_path=repo.repo_path,
            run_dir=paths.run_dir,
            docker_image=docker_image,
            repositoryname=repo_name_for_aikido,
            branchname=branch,
            scan_types=scan_types,
            fail_on=fail_on,
            gating_mode=gating_mode,
            base_commit_id=base_commit_id,
            head_commit_id=head_commit_id or repo.commit,
            gating_output_inside=gating_output_inside,
            force_create_repository_for_branch=force_create_repository_for_branch,
            no_snippets=no_snippets,
            debug=debug,
        )

    # Persist logs for debugging.
    (paths.run_dir / "aikido_local_scanner.stdout.log").write_text(stdout, encoding="utf-8")
    (paths.run_dir / "aikido_local_scanner.stderr.log").write_text(stderr, encoding="utf-8")

    # If the scanner did not write an output file, surface a helpful error.
    if not paths.raw_results.exists():
        raise RuntimeError(
            "Aikido local scanner did not produce a gating-result-output JSON file.\n"
            f"Expected: {paths.raw_results}\n"
            f"Command : {command_str}\n"
            f"stderr  : {stderr[-2000:]}"
        )

    # Count issues (best-effort; file can still be empty/[]).
    issues_count: Optional[int] = None
    try:
        import json

        raw = json.load(open(paths.raw_results, "r", encoding="utf-8"))
        if isinstance(raw, list):
            issues_count = len(raw)
        elif isinstance(raw, dict):
            # normalize._coerce_issues_payload handles wrappers; keep this cheap.
            issues_count = len(raw.get("issues", []) or raw.get("data", []) or [])
    except Exception:
        pass

    metadata = build_std_run_metadata(
        scanner="aikido",
        scanner_version=f"local-scanner:{docker_image}" if not local_bin else "local-scanner:binary",
        repo=repo,
        run_id=run_id,
        command_str=command_str,
        scan_time_seconds=float(elapsed),
        exit_code=int(exit_code),
        extra={
            "aikido_backend": "local",
            "aikido_repositoryname": repo_name_for_aikido,
            "aikido_branchname": branch,
            "aikido_scan_types": scan_types or [],
            "aikido_fail_on": fail_on,
            "aikido_gating_mode": gating_mode,
            "aikido_base_commit_id": base_commit_id,
            "aikido_head_commit_id": head_commit_id or repo.commit,
            "aikido_force_create_repository_for_branch": force_create_repository_for_branch,
            "aikido_no_snippets": no_snippets,
            "issues_count": issues_count,
        },
    )
    write_json(paths.metadata, metadata)

    normalize_aikido_results(paths.raw_results, metadata, paths.normalized)
    return paths, metadata


def execute(
    *,
    git_ref: Optional[str],
    output_root: str,
    skip_trigger: bool,
    mode: str = "cloud",
    repo_path: Optional[str] = None,
    repo_url: Optional[str] = None,
    repositoryname: Optional[str] = None,
    branch: Optional[str] = None,
    branchname: Optional[str] = None,
    scan_types: Optional[List[str]] = None,
    fail_on: str = "low",
    gating_mode: str = "release",
    base_commit_id: Optional[str] = None,
    head_commit_id: Optional[str] = None,
    force_create_repository_for_branch: bool = False,
    no_snippets: bool = False,
    debug: bool = False,
    prefer_binary: bool = False,
    docker_image: Optional[str] = None,
) -> Tuple[RunPaths, Dict[str, Any]]:
    """Dispatch to the chosen backend."""
    mode = (mode or "cloud").strip().lower()
    if mode == "cloud":
        return execute_cloud(git_ref=git_ref, output_root=output_root, skip_trigger=skip_trigger, repositoryname=repositoryname, branch=branch)

    if mode == "local":
        if not repo_path:
            raise SystemExit("Aikido local mode requires --repo-path.")
        return execute_local(
            repo_path=repo_path,
            output_root=output_root,
            repo_url=repo_url,
            git_ref=git_ref,
            repositoryname=repositoryname,
            branch=branch,
            branchname=branchname,
            scan_types=scan_types,
            fail_on=fail_on,
            gating_mode=gating_mode,
            base_commit_id=base_commit_id,
            head_commit_id=head_commit_id,
            force_create_repository_for_branch=force_create_repository_for_branch,
            no_snippets=no_snippets,
            debug=debug,
            prefer_binary=prefer_binary,
            docker_image=docker_image,
        )

    raise SystemExit(f"Unknown Aikido mode: {mode!r} (expected 'cloud' or 'local').")


def cli_entry(
    *,
    git_ref: Optional[str],
    output_root: str,
    skip_trigger: bool,
    mode: str = "cloud",
    repo_path: Optional[str] = None,
    repo_url: Optional[str] = None,
    repositoryname: Optional[str] = None,
    branch: Optional[str] = None,
    branchname: Optional[str] = None,
    scan_types: Optional[List[str]] = None,
    fail_on: str = "low",
    gating_mode: str = "release",
    base_commit_id: Optional[str] = None,
    head_commit_id: Optional[str] = None,
    force_create_repository_for_branch: bool = False,
    no_snippets: bool = False,
    debug: bool = False,
    prefer_binary: bool = False,
    docker_image: Optional[str] = None,
) -> None:
    try:
        paths, _meta = execute(
            git_ref=git_ref,
            output_root=output_root,
            skip_trigger=skip_trigger,
            mode=mode,
            repo_path=repo_path,
            repo_url=repo_url,
            repositoryname=repositoryname,
            branch=branch,
            branchname=branchname,
            scan_types=scan_types,
            fail_on=fail_on,
            gating_mode=gating_mode,
            base_commit_id=base_commit_id,
            head_commit_id=head_commit_id,
            force_create_repository_for_branch=force_create_repository_for_branch,
            no_snippets=no_snippets,
            debug=debug,
            prefer_binary=prefer_binary,
            docker_image=docker_image,
        )
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
