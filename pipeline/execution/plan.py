"""pipeline.execution.plan

Pure planning helpers for :mod:`pipeline.execution.run_case`.

Design rules
------------
This module should stay *pure*:
* no subprocess execution
* no filesystem writes

It may read lightweight process state (e.g. environment variables) indirectly
through scanner hooks declared in :mod:`pipeline.scanners`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from pipeline.core import build_scan_command, filter_scanners_for_track
from pipeline.models import CaseSpec
from pipeline.scanners import SCANNERS, ScannerRunContext
from pipeline.suites.layout import SuitePaths

from .model import GitContext, RunCaseRequest, ToolInvocation


def merge_dicts(a: Optional[Dict[str, Any]], b: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if a:
        out.update(a)
    if b:
        out.update(b)
    return out


def get_case_track(case: CaseSpec) -> Optional[str]:
    """Return the case track label if present (best-effort)."""

    try:
        track = getattr(case, "track", None) or (case.tags or {}).get("track")
        return str(track) if track else None
    except Exception:
        return None


def apply_track_filter(scanners: Sequence[str], case_track: Optional[str]) -> Tuple[List[str], List[str], List[str]]:
    """Filter scanners based on case track.

    Returns
    -------
    (scanners_used, scanners_skipped, notes)

    Notes are human-friendly strings the coordinator may print.
    """

    if not case_track:
        return list(scanners), [], []

    filtered, skipped = filter_scanners_for_track(scanners, str(case_track))
    notes: List[str] = []

    if skipped:
        notes.append(f"⚠️  skipping scanners not in track={case_track!r}: {', '.join(skipped)}")

    if filtered:
        return list(filtered), list(skipped), notes

    # If nothing matches, keep the original list (don't silently do nothing).
    notes.append(f"⚠️  no scanners matched track={case_track!r}; running requested scanners")
    return list(scanners), list(skipped), notes


def required_env_vars(scanner: str) -> Tuple[str, ...]:
    """Return env vars required by a scanner (pure lookup)."""

    info = SCANNERS.get(scanner)
    if info is None:
        return ()
    return tuple(str(v) for v in getattr(info, "required_env", ()) or ())


def build_scanner_extra_args(
    *,
    scanner: str,
    req: RunCaseRequest,
    git_ctx: GitContext,
    suite_paths: Optional[SuitePaths],
) -> Dict[str, Any]:
    """Compute scanner-specific + suite-rooted extra args.

    This function is intentionally side-effect free; required env checks should
    be performed by the coordinator before invoking the tool.
    """

    extra_args: Dict[str, Any] = {}

    info = SCANNERS.get(scanner)
    if info is not None:
        builder = getattr(info, "extra_args_builder", None)
        if builder is not None:
            ctx = ScannerRunContext(git_branch=git_ctx.branch, git_commit=git_ctx.commit)
            built = builder(req, ctx) or {}
            if not isinstance(built, dict):
                raise SystemExit(
                    f"Invalid extra_args_builder for {scanner!r}: expected dict, got {type(built)}"
                )
            extra_args = merge_dicts(extra_args, built)

    # Suite output rooting (all scanners share --output-root)
    if suite_paths is not None:
        extra_args = merge_dicts(extra_args, {"output-root": str(suite_paths.tool_runs_dir / scanner)})

    return extra_args


def build_scan_invocation(*, scanner: str, req: RunCaseRequest, extra_args: Dict[str, Any]) -> ToolInvocation:
    """Build a concrete tool invocation for a scanner (command list only)."""

    cmd = build_scan_command(
        scanner,
        repo_url=req.case.repo.repo_url,
        repo_path=req.case.repo.repo_path,
        extra_args=extra_args,
        python_executable=req.python_executable,
    )
    return ToolInvocation(scanner=scanner, cmd=list(cmd))


def evaluate_git_context(
    *,
    case: CaseSpec,
    actual_branch: Optional[str],
    actual_commit: Optional[str],
) -> Tuple[GitContext, List[str]]:
    """Compare expected vs actual git context and return warnings."""

    warnings: List[str] = []

    if case.branch and actual_branch and case.branch != actual_branch:
        warnings.append(f"case_context_branch_mismatch: expected={case.branch} actual={actual_branch}")
    if case.branch and not actual_branch:
        warnings.append(f"case_context_branch_unknown: expected={case.branch} actual=None")
    if case.commit and actual_commit and case.commit != actual_commit:
        warnings.append(f"case_context_commit_mismatch: expected={case.commit} actual={actual_commit}")
    if case.commit and not actual_commit:
        warnings.append(f"case_context_commit_unknown: expected={case.commit} actual=None")

    return GitContext(branch=actual_branch, commit=actual_commit), warnings


def backfill_case_repo_context(
    *,
    req: RunCaseRequest,
    tool_runs_manifest: Mapping[str, Any],
    git_ctx: GitContext,
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Prefer repo context from tool metadata, fallback to CLI/git.

    Returns
    -------
    (repo_path, branch, commit, probe_repo_path)

    If probe_repo_path is not None, the coordinator may try to detect missing
    branch/commit using git subprocess helpers.
    """

    case_repo_path = req.case.repo.repo_path
    case_repo_commit = git_ctx.commit
    case_repo_branch = git_ctx.branch

    for _tool, info in tool_runs_manifest.items():
        meta = (info or {}).get("metadata") if isinstance(info, dict) else None
        if not isinstance(meta, dict):
            continue

        if not case_repo_path:
            rp = meta.get("repo_path") or meta.get("repo_local_path")
            if rp:
                case_repo_path = str(rp)
        if not case_repo_commit and meta.get("repo_commit"):
            case_repo_commit = str(meta.get("repo_commit"))
        if not case_repo_branch and meta.get("repo_branch"):
            case_repo_branch = str(meta.get("repo_branch"))

    probe_repo_path: Optional[str] = None
    if case_repo_path and (not case_repo_commit or not case_repo_branch):
        probe_repo_path = str(case_repo_path)

    return case_repo_path, case_repo_branch, case_repo_commit, probe_repo_path
