"""pipeline.execution.run_case

Case execution entrypoint.

This module is intentionally small: it coordinates the pure planner
(:mod:`pipeline.execution.plan`) with the side-effecting adapters:

* :mod:`pipeline.execution.runner` – subprocess execution
* :mod:`pipeline.execution.record` – filesystem receipts/manifests

The public API remains stable for backwards compatibility:

* ``RunRequest`` (alias)
* ``run_tools(req)``
* ``_maybe_run_analysis(...)`` (tests import this)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pipeline.core import ROOT_DIR as REPO_ROOT
from pipeline.scanners import SUPPORTED_SCANNERS
from pipeline.suites.layout import SuitePaths

from . import plan, record, runner
from .model import RunCaseRequest, now_iso


# Backwards-compatible alias.
RunRequest = RunCaseRequest


ENV_PATH: Path = REPO_ROOT / ".env"


def _require_env(var: str) -> None:
    if not os.getenv(var):
        raise SystemExit(f"Missing {var}. Put it in {ENV_PATH} (or export it in your shell).")


def _print_invocation_header(
    req: RunRequest, *, scanners: Sequence[str], suite_paths: Optional[SuitePaths]
) -> None:
    if req.invocation_mode == "scan":
        print("\n🚀 Running scan")
        print(f"  Scanner : {scanners[0]}")
        print(f"  Target  : {req.case.label}")
        return

    print("\n🚀 Running benchmark (multi-scanner loop)")
    print(f"  Target   : {req.case.label}")
    print(f"  Repo name: {req.case.runs_repo_name}")
    print(f"  Scanners : {', '.join(scanners)}")
    if suite_paths is not None:
        print(f"  Suite id : {suite_paths.suite_id}")
        print(f"  Suite dir: {suite_paths.suite_dir}")
        print(f"  Case dir : {suite_paths.case_dir}")


def _maybe_run_analysis(
    *,
    req: RunRequest,
    suite_paths: SuitePaths,
    scanners: Sequence[str],
    case_warnings: List[str],
) -> Optional[Dict[str, Any]]:
    """Backwards-compatible wrapper (tests import this symbol)."""

    return record.maybe_run_analysis(
        req=req,
        suite_paths=suite_paths,
        scanners=scanners,
        case_warnings=case_warnings,
    )


def run_tools(req: RunRequest) -> int:
    """Run one or more scanners against a single case.

    This is the shared implementation for scan + benchmark mode.

    Returns an exit code.
    """

    scanners_requested = [s for s in req.scanners if s in SUPPORTED_SCANNERS]
    if not scanners_requested:
        raise SystemExit("No valid scanners specified.")

    if req.invocation_mode not in ("scan", "benchmark"):
        raise SystemExit(f"Invalid invocation_mode: {req.invocation_mode}")

    scanners_requested = list(scanners_requested)

    # Collected non-fatal issues for this case run.
    case_warnings: List[str] = []

    # Optional track enforcement (useful when mixing SAST/SCA/IaC case sets).
    case_track = plan.get_case_track(req.case)
    scanners, skipped_by_track, notes = plan.apply_track_filter(scanners_requested, case_track)
    for msg in notes:
        print(f"  {msg}")
    if skipped_by_track:
        case_warnings.append(
            f"scanners_skipped_by_track: track={case_track} skipped={','.join(skipped_by_track)}"
        )

    # Suite handling (directory layout + optional GT capture)
    suite_paths = record.init_suite_paths(req, case_warnings=case_warnings)

    # Human-friendly header
    _print_invocation_header(req, scanners=scanners, suite_paths=suite_paths)

    started = now_iso()

    # Capture git context early so the case manifest can be trusted even if
    # downstream tools write zero findings.
    actual_branch = runner.detect_git_branch(req.case.repo.repo_path)
    actual_commit = runner.detect_git_commit(req.case.repo.repo_path)
    git_ctx, git_warnings = plan.evaluate_git_context(
        case=req.case,
        actual_branch=actual_branch,
        actual_commit=actual_commit,
    )
    case_warnings.extend(git_warnings)

    tool_runs_manifest: Dict[str, Any] = {}
    overall = 0

    # -------------------------------------------------------------------
    # Scan loop
    # -------------------------------------------------------------------

    for scanner_key in scanners:
        if req.invocation_mode == "benchmark":
            print("\n----------------------------------------")
            print(f"▶ {scanner_key}")

        # Preflight env vars declared by the scanner integration.
        for var in plan.required_env_vars(scanner_key):
            _require_env(var)

        extra_args = plan.build_scanner_extra_args(
            scanner=scanner_key,
            req=req,
            suite_paths=suite_paths,
            git_ctx=git_ctx,
        )

        # Small UX: show derived project-key when present (primarily Sonar).
        if "project-key" in extra_args:
            print(f"  Sonar project key : {extra_args.get('project-key')}")

        invocation = plan.build_scan_invocation(scanner=scanner_key, req=req, extra_args=extra_args)
        execution = runner.run_invocation(invocation, dry_run=req.dry_run, quiet=req.quiet)

        if execution.exit_code != 0:
            overall = execution.exit_code

        # Record run info (best-effort) when using suites
        if suite_paths is not None:
            record.record_tool_run_manifest(
                scanner=scanner_key,
                suite_paths=suite_paths,
                req=req,
                execution=execution,
                case_warnings=case_warnings,
                tool_runs_manifest=tool_runs_manifest,
            )

    # -------------------------------------------------------------------
    # Post-processing: backfill repo context and write manifests
    # -------------------------------------------------------------------

    case_repo_path, case_repo_branch, case_repo_commit, probe_repo_path = (
        plan.backfill_case_repo_context(
            req=req,
            tool_runs_manifest=tool_runs_manifest,
            git_ctx=git_ctx,
        )
    )

    # If we discovered a repo path but branch/commit are still missing, try git.
    if probe_repo_path:
        if not case_repo_commit:
            case_repo_commit = runner.detect_git_commit(probe_repo_path)
        if not case_repo_branch:
            case_repo_branch = runner.detect_git_branch(probe_repo_path)

    analysis_summary: Optional[Dict[str, Any]] = None
    manifest: Optional[Dict[str, Any]] = None

    # Write a *pre-analysis* case manifest so analysis stages (diagnostics + GT
    # marker scoring) can read case.json reliably.
    if suite_paths is not None:
        manifest = record.write_case_manifest_file(
            paths=suite_paths,
            invocation_mode=req.invocation_mode,
            argv=req.argv,
            python_executable=req.python_executable,
            skip_analysis=bool(req.skip_analysis),
            repo_label=req.case.label,
            repo_url=req.case.repo.repo_url,
            repo_path=case_repo_path,
            runs_repo_name=req.case.runs_repo_name,
            expected_branch=req.case.branch,
            expected_commit=req.case.commit,
            track=case_track,
            tags=dict(req.case.tags or {}),
            git_branch=case_repo_branch,
            git_commit=case_repo_commit,
            started=started,
            finished=None,
            scanners_requested=scanners_requested,
            scanners_used=scanners,
            tool_runs=tool_runs_manifest,
            analysis=None,
            warnings=case_warnings,
            errors=[],
        )

        analysis_summary = _maybe_run_analysis(
            req=req,
            suite_paths=suite_paths,
            scanners=scanners,
            case_warnings=case_warnings,
        )

    finished = now_iso()

    # Final case manifest + suite artifacts
    if suite_paths is not None:
        manifest = record.write_case_manifest_file(
            paths=suite_paths,
            invocation_mode=req.invocation_mode,
            argv=req.argv,
            python_executable=req.python_executable,
            skip_analysis=bool(req.skip_analysis),
            repo_label=req.case.label,
            repo_url=req.case.repo.repo_url,
            repo_path=case_repo_path,
            runs_repo_name=req.case.runs_repo_name,
            expected_branch=req.case.branch,
            expected_commit=req.case.commit,
            track=case_track,
            tags=dict(req.case.tags or {}),
            git_branch=case_repo_branch,
            git_commit=case_repo_commit,
            started=started,
            finished=finished,
            scanners_requested=scanners_requested,
            scanners_used=scanners,
            tool_runs=tool_runs_manifest,
            analysis=analysis_summary,
            warnings=case_warnings,
            errors=[],
        )

        record.update_suite_indexes(suite_paths, manifest)

        print("\n📦 Case complete")
        print(f"  Suite id : {suite_paths.suite_id}")
        print(f"  Suite dir: {suite_paths.suite_dir}")
        print(f"  Case dir : {suite_paths.case_dir}")
        print(f"  Tool runs: {suite_paths.tool_runs_dir}")
        print(f"  Analysis : {suite_paths.analysis_dir if not req.skip_analysis else '(skipped)'}")
        print(f"  Manifest : {suite_paths.case_json_path}")
        print(f"  Summary  : {suite_paths.suite_summary_path}")

    # Exit messaging
    if overall == 0:
        if req.invocation_mode == "scan":
            print("\n✅ Scan completed.")
        else:
            print("\n✅ Benchmark completed (all scanners exited 0).")
    else:
        if req.invocation_mode == "scan":
            print(f"\n⚠️ Scan finished with exit code {overall}")
        else:
            print(f"\n⚠️ Benchmark completed with non-zero exit code: {overall}")

    return int(overall)
