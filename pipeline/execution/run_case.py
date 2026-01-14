"""pipeline.execution.run_case

Case execution entrypoint.

This module contains the implementation previously located in
``pipeline.orchestrator.run_tools``.

Why this exists
---------------
``pipeline/orchestrator.py`` was growing into a large "composition root" that
mixed multiple concerns (running tools vs running analysis). Splitting the
implementation into focused modules keeps behavior the same while making the
"where do I look?" story clearer.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pipeline.core import (
    ROOT_DIR as REPO_ROOT,
    build_scan_command,
    filter_scanners_for_track,
)
from pipeline.suites.manifests import (
    update_latest_pointer,
    update_suite_artifacts,
    write_case_manifest,
)
from pipeline.suites.layout import (
    SuitePaths,
    discover_latest_run_dir,
    discover_repo_dir,
    ensure_suite_dirs,
    get_suite_paths,
    new_suite_id,
)
from pipeline.models import CaseSpec
from pipeline.scanners import SCANNERS, SUPPORTED_SCANNERS, ScannerRunContext
from tools.io import write_json


ENV_PATH: Path = REPO_ROOT / ".env"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_json_if_exists(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists() or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _run_one(cmd: List[str], *, dry_run: bool, quiet: bool) -> int:
    print("  Command :", " ".join(cmd))
    if dry_run:
        print("  (dry-run: not executing)")
        return 0

    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")

    if quiet:
        result = subprocess.run(
            cmd,
            env=env,
            cwd=str(REPO_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        result = subprocess.run(cmd, env=env, cwd=str(REPO_ROOT))

    return int(result.returncode)


def _require_env(var: str) -> None:
    if not os.getenv(var):
        raise SystemExit(f"Missing {var}. Put it in {ENV_PATH} (or export it in your shell).")


def _detect_git_branch(repo_path: Optional[str]) -> Optional[str]:
    """Best-effort detect current git branch name for a local repo checkout."""
    if not repo_path:
        return None
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_path), "rev-parse", "--abbrev-ref", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=20,
        ).strip()
        if not out or out == "HEAD":
            return None
        return out
    except Exception:
        return None


def _detect_git_commit(repo_path: Optional[str]) -> Optional[str]:
    """Best-effort detect current git commit SHA for a local repo checkout."""
    if not repo_path:
        return None
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=20,
        ).strip()
        return out or None
    except Exception:
        return None


def _capture_optional_benchmark_yaml(
    repo_path: Optional[str],
    case_dir: Path,
    *,
    warnings: Optional[List[str]] = None,
) -> None:
    """Best-effort capture of benchmark YAML inputs for a case.

    Some suites (e.g. Durinn micro-suites) contain benchmark metadata like:
      benchmark/gt_catalog.yaml
      benchmark/suite_sets.yaml

    Many targets (e.g. Juice Shop) will not have these files.

    This function is intentionally no-break:
    - If repo_path is missing or files don't exist, it does nothing.
    - Any exception is swallowed so scans are never blocked by capture.

    Captured files are copied to:
      <case_dir>/gt/

    This makes each case directory self-contained for later DB ingestion.
    """

    if not repo_path:
        return
    try:
        bench = Path(repo_path) / "benchmark"
        if not bench.exists():
            return

        gt_dir = Path(case_dir) / "gt"
        gt_dir.mkdir(parents=True, exist_ok=True)

        candidates = [
            "gt_catalog.yaml",
            "gt_catalog.yml",
            "suite_sets.yaml",
            "suite_sets.yml",
        ]
        for name in candidates:
            src = bench / name
            if src.exists() and src.is_file():
                shutil.copy2(src, gt_dir / name)
    except Exception as e:
        if warnings is not None:
            warnings.append(f"benchmark_yaml_capture_failed: {e}")
        return


def _merge_dicts(a: Optional[Dict[str, Any]], b: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if a:
        out.update(a)
    if b:
        out.update(b)
    return out


def _write_run_json(
    run_dir: Path,
    *,
    suite_id: str,
    case_id: str,
    tool: str,
    repo_name: str,
    exit_code: int,
    command: str,
    started: Optional[str] = None,
    finished: Optional[str] = None,
) -> None:
    """Write run_dir/run.json (DB-ingestion friendly pointer file)."""

    run_id = run_dir.name

    def _pick_first(candidates: list[str]) -> Optional[str]:
        for name in candidates:
            p = run_dir / name
            if p.exists() and p.is_file():
                return name
        return None

    normalized_name = _pick_first(["normalized.json", f"{repo_name}.normalized.json"])
    raw_name = _pick_first(["raw.sarif", "raw.json", f"{repo_name}.sarif", f"{repo_name}.json"])
    metadata_name = _pick_first(["metadata.json"])
    logs_dir = run_dir / "logs"
    logs_dir_name = "logs" if logs_dir.exists() and logs_dir.is_dir() else None

    data: Dict[str, Any] = {
        "suite_id": suite_id,
        "case_id": case_id,
        "tool": tool,
        "run_id": run_id,
        "started": started,
        "finished": finished,
        "exit_code": int(exit_code),
        "command": command,
        "artifacts": {
            "normalized": normalized_name,
            "raw": raw_name,
            "metadata": metadata_name,
            "logs_dir": logs_dir_name,
        },
    }

    write_json(run_dir / "run.json", data)


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RunRequest:
    invocation_mode: str  # "scan" | "benchmark"
    case: CaseSpec
    repo_id: str

    scanners: Sequence[str]

    # suite writing
    suite_root: Path
    suite_id: Optional[str] = None
    use_suite: bool = True

    # execution
    dry_run: bool = False
    quiet: bool = False

    # post-processing
    skip_analysis: bool = False
    tolerance: int = 3
    gt_tolerance: int = 0
<<<<<<< ours
=======
    gt_source: str = "auto"
>>>>>>> theirs
    analysis_filter: str = "security"

    # scope filtering (analysis only)
    exclude_prefixes: Sequence[str] = ()
    include_harness: bool = False

    # tool overrides
    sonar_project_key: Optional[str] = None
    aikido_git_ref: Optional[str] = None

    # manifest provenance
    argv: Optional[Sequence[str]] = None
    python_executable: Optional[str] = None


# ---------------------------------------------------------------------------
# Coordinator helpers (keep run_tools() readable)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GitContext:
    """Best-effort git context for the scanned repo checkout."""

    branch: Optional[str]
    commit: Optional[str]


@dataclass(frozen=True)
class ToolExecution:
    cmd: List[str]
    exit_code: int
    started: str
    finished: str

    @property
    def command_str(self) -> str:
        return " ".join(self.cmd)


def _get_case_track(req: RunRequest) -> Optional[str]:
    """Return the case track label if present (best-effort)."""

    try:
        track = getattr(req.case, "track", None) or (req.case.tags or {}).get("track")
        return str(track) if track else None
    except Exception:
        return None


def _apply_track_filter(scanners: List[str], case_track: Optional[str]) -> tuple[List[str], List[str]]:
    """Filter scanners based on case track and print UX warnings.

    Returns (scanners_used, scanners_skipped).
    """

    if not case_track:
        return scanners, []

    filtered, skipped = filter_scanners_for_track(scanners, str(case_track))
    if skipped:
        # Keep this in warnings so it shows up in case.json.
        # (We also print it for interactive UX.)
        print(f"  ⚠️  skipping scanners not in track={case_track!r}: {', '.join(skipped)}")

    if filtered:
        return list(filtered), list(skipped)

    # If nothing matches, keep the original list (don't silently do nothing).
    print(f"  ⚠️  no scanners matched track={case_track!r}; running requested scanners")
    return scanners, list(skipped)


def _compute_suite_paths_and_init(req: RunRequest, *, case_warnings: List[str]) -> Optional[SuitePaths]:
    if not req.use_suite:
        return None

    sid = str(req.suite_id) if req.suite_id else new_suite_id()
    suite_paths = get_suite_paths(case_id=req.case.case_id, suite_id=sid, suite_root=req.suite_root)
    ensure_suite_dirs(suite_paths)
    update_latest_pointer(suite_paths)

    # Optional: capture suite GT YAML into the case folder for reproducibility
    _capture_optional_benchmark_yaml(req.case.repo.repo_path, suite_paths.case_dir, warnings=case_warnings)

    return suite_paths


def _print_invocation_header(req: RunRequest, *, scanners: Sequence[str], suite_paths: Optional[SuitePaths]) -> None:
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


def _capture_git_context(req: RunRequest, *, case_warnings: List[str]) -> GitContext:
    """Capture git branch/commit for the scanned repo and record mismatches."""

    actual_branch = _detect_git_branch(req.case.repo.repo_path)
    actual_commit = _detect_git_commit(req.case.repo.repo_path)

    # Record obvious mismatches immediately (still non-fatal).
    if req.case.branch and actual_branch and req.case.branch != actual_branch:
        case_warnings.append(
            f"case_context_branch_mismatch: expected={req.case.branch} actual={actual_branch}"
        )
    if req.case.branch and not actual_branch:
        case_warnings.append(f"case_context_branch_unknown: expected={req.case.branch} actual=None")
    if req.case.commit and actual_commit and req.case.commit != actual_commit:
        case_warnings.append(
            f"case_context_commit_mismatch: expected={req.case.commit} actual={actual_commit}"
        )
    if req.case.commit and not actual_commit:
        case_warnings.append(f"case_context_commit_unknown: expected={req.case.commit} actual=None")

    return GitContext(branch=actual_branch, commit=actual_commit)


def _compute_extra_args(
    *,
    scanner: str,
    req: RunRequest,
    suite_paths: Optional[SuitePaths],
    git_ctx: GitContext,
) -> Dict[str, Any]:
    extra_args: Dict[str, Any] = {}

    # Scanner-specific quirks (env requirements + derived args) are centralized
    # in pipeline.scanners as pure hooks.
    info = SCANNERS.get(scanner)
    if info is not None:
        for var in getattr(info, "required_env", ()):
            _require_env(str(var))

        builder = getattr(info, "extra_args_builder", None)
        if builder is not None:
            ctx = ScannerRunContext(git_branch=git_ctx.branch, git_commit=git_ctx.commit)
            built = builder(req, ctx) or {}
            if not isinstance(built, dict):
                raise SystemExit(f"Invalid extra_args_builder for {scanner!r}: expected dict, got {type(built)}")
            extra_args = _merge_dicts(extra_args, built)

    # Small UX: show derived project-key when present (primarily Sonar).
    if "project-key" in extra_args:
        print(f"  Sonar project key : {extra_args.get('project-key')}")

    # Suite output rooting (all scanners share --output-root)
    if suite_paths is not None:
        extra_args = _merge_dicts(extra_args, {"output-root": str(suite_paths.tool_runs_dir / scanner)})

    return extra_args


def _execute_scanner(*, cmd: List[str], req: RunRequest) -> ToolExecution:
    tool_started = _now_iso()
    code = _run_one(cmd, dry_run=req.dry_run, quiet=req.quiet)
    tool_finished = _now_iso()
    return ToolExecution(cmd=cmd, exit_code=int(code), started=tool_started, finished=tool_finished)


def _record_tool_run_manifest(
    *,
    scanner: str,
    suite_paths: SuitePaths,
    req: RunRequest,
    execution: ToolExecution,
    case_warnings: List[str],
    tool_runs_manifest: Dict[str, Any],
) -> None:
    """Best-effort discovery of tool outputs + run.json writing."""

    tool_out_root = suite_paths.tool_runs_dir / scanner

    # Discover the tool run root (layout v2: <output_root>/<run_id>/... or v1: <output_root>/<repo>/<run_id>/...)
    run_root_dir = discover_repo_dir(tool_out_root, prefer=req.case.runs_repo_name)
    run_dir = discover_latest_run_dir(run_root_dir) if run_root_dir else None
    metadata = _load_json_if_exists((run_dir / "metadata.json") if run_dir else Path("/nonexistent"))

    # Prefer the scanner-captured local checkout path for downstream analysis/GT extraction.
    scanned_repo_dir = None
    if isinstance(metadata, dict):
        scanned_repo_dir = metadata.get("repo_path") or metadata.get("repo_local_path")
    if not scanned_repo_dir:
        scanned_repo_dir = req.case.repo.repo_path

    # Defensive check: repo_dir should never point at the tool output root.
    # If it does, GT marker extraction and diagnostics will break.
    try:
        if scanned_repo_dir:
            srd = Path(str(scanned_repo_dir)).resolve()
            out_root = tool_out_root.resolve()
            if srd == out_root or out_root in srd.parents:
                case_warnings.append(f"repo_dir_suspicious:{scanner}:repo_dir_points_into_output_root:{srd}")
    except Exception:
        pass

    if run_dir:
        try:
            _write_run_json(
                run_dir,
                suite_id=suite_paths.suite_id,
                case_id=suite_paths.case_id,
                tool=scanner,
                repo_name=req.case.runs_repo_name,
                exit_code=execution.exit_code,
                command=execution.command_str,
                started=execution.started,
                finished=execution.finished,
            )
        except Exception as e:
            case_warnings.append(f"write_run_json_failed:{scanner}:{run_dir}: {e}")

    run_json_path = str(run_dir / "run.json") if run_dir else None

    tool_runs_manifest[scanner] = {
        "exit_code": execution.exit_code,
        "command": execution.command_str,
        "started": execution.started,
        "finished": execution.finished,
        "output_root": str(tool_out_root),
        "run_root": str(run_root_dir) if run_root_dir else None,
        "repo_dir": str(scanned_repo_dir) if scanned_repo_dir else None,
        "run_id": run_dir.name if run_dir else None,
        "run_dir": str(run_dir) if run_dir else None,
        "run_json": run_json_path,
        "metadata": metadata,
    }


def _backfill_case_repo_context(
    *,
    req: RunRequest,
    tool_runs_manifest: Dict[str, Any],
    git_ctx: GitContext,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Prefer repo context from tool metadata, fallback to CLI/git."""

    # Backfill scanned repo context from tool metadata for runs where the CLI did not receive --repo-path.
    # This is critical for GT marker extraction and context diagnostics.
    case_repo_path = req.case.repo.repo_path
    case_repo_commit = git_ctx.commit
    case_repo_branch = git_ctx.branch

    for _tool, info in tool_runs_manifest.items():
        meta = (info or {}).get("metadata")
        if not isinstance(meta, dict):
            continue
        if not case_repo_path:
            rp = meta.get("repo_path") or meta.get("repo_local_path")
            if rp:
                case_repo_path = rp
        if not case_repo_commit and meta.get("repo_commit"):
            case_repo_commit = meta.get("repo_commit")
        if not case_repo_branch and meta.get("repo_branch"):
            case_repo_branch = meta.get("repo_branch")

    # If we discovered a repo path but branch/commit are still missing, try git.
    if case_repo_path and (not case_repo_commit or not case_repo_branch):
        try:
            from pathlib import Path as _Path

            from tools.core import get_git_branch as _get_git_branch
            from tools.core import get_git_commit as _get_git_commit

            _p = _Path(case_repo_path)
            if not case_repo_commit:
                case_repo_commit = _get_git_commit(_p)
            if not case_repo_branch:
                case_repo_branch = _get_git_branch(_p)
        except Exception:
            pass

    return case_repo_path, case_repo_branch, case_repo_commit


def _maybe_run_analysis(
    *,
    req: RunRequest,
    suite_paths: SuitePaths,
    scanners: Sequence[str],
    case_warnings: List[str],
) -> Optional[Dict[str, Any]]:
    """Run analysis suite (benchmark mode only)."""

    # Auto-analysis (only makes sense when bundling)
    if req.invocation_mode != "benchmark" or req.skip_analysis:
        return None

    print("\n----------------------------------------")
    print("▶ analysis suite")

    from pipeline.analysis.run_discovery import find_latest_normalized_json

    available_tools: List[str] = []
    for tool in scanners:
        try:
            find_latest_normalized_json(
                runs_dir=suite_paths.tool_runs_dir,
                tool=tool,
                repo_name=req.case.runs_repo_name,
            )
            available_tools.append(tool)
        except FileNotFoundError:
            msg = f"missing_normalized_json:{tool}"
            case_warnings.append(msg)
            print(f"  ⚠️  missing normalized JSON for {tool}; skipping it in analysis")

    if not available_tools:
        print("  ⚠️  no tool outputs found; skipping analysis")
        return None

    from pipeline.analysis.analyze_suite import run_suite

    analysis_summary = run_suite(
        repo_name=req.case.runs_repo_name,
        tools=available_tools,
        runs_dir=suite_paths.tool_runs_dir,
        out_dir=suite_paths.analysis_dir,
        tolerance=int(req.tolerance),
        gt_tolerance=int(req.gt_tolerance),
<<<<<<< ours
=======
        gt_source=str(req.gt_source),
>>>>>>> theirs
        mode=str(req.analysis_filter),
        exclude_prefixes=req.exclude_prefixes,
        include_harness=bool(req.include_harness),
        formats=["json", "csv"],
    )
    print(f"  ✅ analysis complete: {suite_paths.analysis_dir}")
    return analysis_summary


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------


def run_tools(req: RunRequest) -> int:
    """Run one or more scanners against a single case.

    This is the shared implementation for scan + benchmark mode.

    Returns an exit code.
    """

    scanners_requested = [s for s in req.scanners if s in SUPPORTED_SCANNERS]
    if not scanners_requested:
        raise SystemExit("No valid scanners specified.")

    scanners_requested = list(scanners_requested)

    if req.invocation_mode not in ("scan", "benchmark"):
        raise SystemExit(f"Invalid invocation_mode: {req.invocation_mode}")

    # Collected non-fatal issues for this case run.
    case_warnings: List[str] = []

    # Optional track enforcement (useful when mixing SAST/SCA/IaC case sets).
    # If a case declares a track, only run scanners that claim to support it.
    # Unknown tracks do not filter scanners (best-effort).
    case_track = _get_case_track(req)
    scanners, skipped_by_track = _apply_track_filter(list(scanners_requested), case_track)
    if skipped_by_track:
        case_warnings.append(
            f"scanners_skipped_by_track: track={case_track} skipped={','.join(skipped_by_track)}"
        )

    # Suite handling (directory layout + optional GT capture)
    suite_paths = _compute_suite_paths_and_init(req, case_warnings=case_warnings)

    # Human-friendly header
    _print_invocation_header(req, scanners=scanners, suite_paths=suite_paths)

    started = _now_iso()

    # Capture git context early so the case manifest can be trusted even if
    # downstream tools write zero findings.
    git_ctx = _capture_git_context(req, case_warnings=case_warnings)

    tool_runs_manifest: Dict[str, Any] = {}
    overall = 0

    # -------------------------------------------------------------------
    # Scan loop
    # -------------------------------------------------------------------

    for scanner in scanners:
        if req.invocation_mode == "benchmark":
            print("\n----------------------------------------")
            print(f"▶ {scanner}")

        extra_args = _compute_extra_args(
            scanner=scanner,
            req=req,
            suite_paths=suite_paths,
            git_ctx=git_ctx,
        )

        cmd = build_scan_command(
            scanner,
            repo_url=req.case.repo.repo_url,
            repo_path=req.case.repo.repo_path,
            extra_args=extra_args,
            python_executable=req.python_executable,
        )

        execution = _execute_scanner(cmd=cmd, req=req)

        if execution.exit_code != 0:
            overall = execution.exit_code

        # Record run info (best-effort) when using suites
        if suite_paths is not None:
            _record_tool_run_manifest(
                scanner=scanner,
                suite_paths=suite_paths,
                req=req,
                execution=execution,
                case_warnings=case_warnings,
                tool_runs_manifest=tool_runs_manifest,
            )

    # -------------------------------------------------------------------
    # Post-processing: backfill repo context and write manifests
    # -------------------------------------------------------------------

    case_repo_path, case_repo_branch, case_repo_commit = _backfill_case_repo_context(
        req=req,
        tool_runs_manifest=tool_runs_manifest,
        git_ctx=git_ctx,
    )

    analysis_summary: Optional[Dict[str, Any]] = None
    manifest: Optional[Dict[str, Any]] = None

    # Write a *pre-analysis* case manifest so analysis stages (diagnostics + GT
    # marker scoring) can read case.json reliably.
    if suite_paths is not None:
        manifest = write_case_manifest(
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

    finished = _now_iso()

    # Final case manifest + suite artifacts
    if suite_paths is not None:
        # Final case manifest + suite-level indexes
        manifest = write_case_manifest(
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

        update_suite_artifacts(suite_paths, manifest)

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
