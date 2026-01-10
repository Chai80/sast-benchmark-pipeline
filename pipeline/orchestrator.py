"""pipeline.orchestrator

High-level orchestration entrypoints for the Durinn benchmark pipeline.

Goal
----
Phase 2 of the CLI refactor moves *mode logic* (scan/benchmark/analyze)
*out of* ``sast_cli.py`` and into this module.

Design principles
-----------------
- Keep the CLI thin: parse args + resolve targets + call orchestrator functions.
- Keep filesystem layout rules centralized (suite/case via :mod:`pipeline.layout`).
- Keep scanner command building centralized (via :mod:`pipeline.core`).
- Never crash a scan because suite summary writing failed (best-effort manifests).

This module is intentionally "boring": it wires together existing components.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pipeline.scanners import SUPPORTED_SCANNERS
from pipeline.core import (
    build_scan_command,
    derive_sonar_project_key,
    filter_scanners_for_track,
)
from pipeline.layout import (
    SuitePaths,
    discover_latest_run_dir,
    discover_repo_dir,
    ensure_suite_dirs,
    get_suite_paths,
    new_suite_id,
    resolve_case_dir,
    update_suite_artifacts,
    write_latest_suite_pointer,
)
from pipeline.models import CaseSpec


REPO_ROOT: Path = Path(__file__).resolve().parents[1]
ENV_PATH: Path = REPO_ROOT / ".env"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _pipeline_git_commit() -> Optional[str]:
    """Best-effort commit hash for *this* pipeline repo (not the scanned repo)."""
    try:
        out = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return out or None
    except Exception:
        return None


def _runtime_environment() -> Dict[str, Any]:
    """Runtime provenance captured into manifests (safe, no secrets)."""
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "pipeline_git_commit": _pipeline_git_commit(),
    }


def _load_json_if_exists(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists() or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


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
        bench = Path(repo_path) / 'benchmark'
        if not bench.exists():
            return

        gt_dir = Path(case_dir) / 'gt'
        gt_dir.mkdir(parents=True, exist_ok=True)

        candidates = [
            'gt_catalog.yaml',
            'gt_catalog.yml',
            'suite_sets.yaml',
            'suite_sets.yml',
        ]
        for name in candidates:
            src = bench / name
            if src.exists() and src.is_file():
                shutil.copy2(src, gt_dir / name)
    except Exception as e:
        if warnings is not None:
            warnings.append(f"benchmark_yaml_capture_failed: {e}")
        return

def _sonar_extra_args(*, repo_id: str, sonar_project_key: Optional[str]) -> Dict[str, str]:
    _require_env("SONAR_ORG")
    _require_env("SONAR_TOKEN")

    if sonar_project_key:
        project_key = sonar_project_key
    else:
        project_key = derive_sonar_project_key(os.environ["SONAR_ORG"], repo_id)

    return {"project-key": project_key}


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

    (run_dir / "run.json").write_text(json.dumps(data, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AnalyzeRequest:
    metric: str
    case: CaseSpec

    # suite-aware resolution
    suite_root: Path
    suite_id: Optional[str] = None
    case_path: Optional[str] = None

    # legacy analyze
    runs_dir: Optional[Path] = None

    tools: Sequence[str] = ()
    output_format: str = "text"

    out: Optional[str] = None
    analysis_out_dir: Optional[str] = None

    tolerance: int = 3
    analysis_filter: str = "security"
    max_unique: int = 25


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
    analysis_filter: str = "security"

    # tool overrides
    sonar_project_key: Optional[str] = None
    aikido_git_ref: Optional[str] = None

    # manifest provenance
    argv: Optional[Sequence[str]] = None
    python_executable: Optional[str] = None


# ---------------------------------------------------------------------------
# Public entrypoints
# ---------------------------------------------------------------------------


def run_analyze(req: AnalyzeRequest) -> int:
    """Run analysis for an existing run set (suite/case aware)."""

    metric = (req.metric or "hotspots").strip()
    if metric not in ("hotspots", "suite"):
        raise SystemExit(f"Invalid metric: {metric}")

    tools = [t for t in req.tools if t in SUPPORTED_SCANNERS]
    if not tools:
        raise SystemExit("No valid tools specified for analyze mode.")

    # Resolve input: case_path overrides suite_id.
    case_dir: Optional[Path] = None
    if req.case_path:
        case_dir = Path(req.case_path).resolve()
    elif req.suite_id:
        case_dir = resolve_case_dir(
            case_id=req.case.case_id,
            suite_id=str(req.suite_id),
            suite_root=req.suite_root,
        )

    if case_dir is not None:
        # v2 layout: tool_runs/ (preferred). v1: scans/ (legacy fallback).
        runs_dir = case_dir / "tool_runs"
        if not runs_dir.exists():
            legacy = case_dir / "scans"
            if legacy.exists():
                runs_dir = legacy
        default_out_dir = case_dir / "analysis"
    else:
        if req.runs_dir is None:
            raise SystemExit("Analyze mode requires --suite-id/--case-path OR --runs-dir (legacy).")
        runs_dir = Path(req.runs_dir).resolve()
        default_out_dir = runs_dir / "analysis" / req.case.runs_repo_name

    if metric == "suite":
        out_dir = Path(req.analysis_out_dir).resolve() if req.analysis_out_dir else default_out_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        from pipeline.analysis.analyze_suite import run_suite

        summary = run_suite(
            repo_name=req.case.runs_repo_name,
            tools=tools,
            runs_dir=runs_dir,
            out_dir=out_dir,
            tolerance=int(req.tolerance),
            mode=str(req.analysis_filter),
            formats=["json", "csv"],
        )

        print("\n✅ Analysis suite complete")
        print(f"  Repo (runs dir): {req.case.runs_repo_name}")
        print(f"  Tools         : {', '.join(tools)}")
        print(f"  Runs dir      : {runs_dir}")
        print(f"  Output dir    : {out_dir}")
        print(f"  Benchmark pack: {out_dir / 'benchmark_pack.json'}")

        print(json.dumps(summary, indent=2))
        return 0

    # metric == hotspots
    out_path = Path(req.out) if req.out else (default_out_dir / "latest_hotspots_by_file.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    from pipeline.analysis.unique_overview import analyze_latest_hotspots_for_repo, print_text_report

    try:
        report = analyze_latest_hotspots_for_repo(
            req.case.runs_repo_name,
            tools=list(tools),
            runs_dir=runs_dir,
        )
    except FileNotFoundError as e:
        print("\n⚠️  No normalized runs found for analysis.")
        print("   Expected layout:")
        print("     v2: <runs_dir>/<tool>/<run_id>/normalized.json")
        print("     v1: <runs_dir>/<tool>/<repo_name>/<run_id>/<repo_name>.normalized.json")
        print(f"   runs_dir       : {runs_dir}")
        print(f"   repo_name      : {req.case.runs_repo_name}")
        print(f"   tools          : {', '.join(tools)}")
        print(f"\n   Details: {e}")
        return 1

    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n📊 Hotspots-by-file report")
    print(f"  Repo (runs dir): {req.case.runs_repo_name}")
    print(f"  Tools         : {', '.join(tools)}")
    print(f"  Runs dir      : {runs_dir}")
    print(f"  Saved report  : {out_path}")

    if req.output_format == "json":
        print(json.dumps(report, indent=2))
    else:
        print_text_report(report, max_unique=int(req.max_unique))

    return 0


def run_tools(req: RunRequest) -> int:
    """Run one or more scanners against a single case.

    This is the shared implementation for scan + benchmark mode.

    Returns an exit code.
    """

    scanners = [s for s in req.scanners if s in SUPPORTED_SCANNERS]
    if not scanners:
        raise SystemExit("No valid scanners specified.")

    scanners_requested = list(scanners)

    skipped_by_track: List[str] = []

    # Optional track enforcement (useful when mixing SAST/SCA/IaC case sets).
    # If a case declares a track, only run scanners that claim to support it.
    # Unknown tracks do not filter scanners (best-effort).
    case_track = None
    try:
        case_track = (req.case.track or (req.case.tags or {}).get("track"))  # type: ignore[attr-defined]
    except Exception:
        case_track = None
    if case_track:
        filtered, skipped = filter_scanners_for_track(scanners, str(case_track))
        if skipped:
            skipped_by_track = list(skipped)
            # Keep this in warnings so it shows up in case.json.
            # (We also print it for interactive UX.)
            print(f"  ⚠️  skipping scanners not in track={case_track!r}: {', '.join(skipped)}")
        if filtered:
            scanners = filtered
        else:
            # If nothing matches, keep the original list (don't silently do nothing).
            print(f"  ⚠️  no scanners matched track={case_track!r}; running requested scanners")

    if req.invocation_mode not in ("scan", "benchmark"):
        raise SystemExit(f"Invalid invocation_mode: {req.invocation_mode}")

    # Collected non-fatal issues for this case run.
    case_warnings: List[str] = []

    if skipped_by_track:
        case_warnings.append(
            f"scanners_skipped_by_track: track={case_track} skipped={','.join(skipped_by_track)}"
        )

    # Suite handling
    bundle: Optional[SuitePaths] = None
    sid: Optional[str] = None
    if req.use_suite:
        sid = str(req.suite_id) if req.suite_id else new_suite_id()
        bundle = get_suite_paths(case_id=req.case.case_id, suite_id=sid, suite_root=req.suite_root)
        ensure_suite_dirs(bundle)
        write_latest_suite_pointer(bundle)
        # Optional: capture suite GT YAML into the case folder for reproducibility
        _capture_optional_benchmark_yaml(req.case.repo.repo_path, bundle.case_dir, warnings=case_warnings)

    # Print header
    if req.invocation_mode == "scan":
        print("\n🚀 Running scan")
        print(f"  Scanner : {scanners[0]}")
        print(f"  Target  : {req.case.label}")
    else:
        print("\n🚀 Running benchmark (multi-scanner loop)")
        print(f"  Target   : {req.case.label}")
        print(f"  Repo name: {req.case.runs_repo_name}")
        print(f"  Scanners : {', '.join(scanners)}")
        if bundle is not None:
            print(f"  Suite id : {bundle.bundle_id}")
            print(f"  Suite dir: {bundle.suite_dir}")
            print(f"  Case dir : {bundle.case_dir}")

    started = _now_iso()

    # Capture git context early so the case manifest can be trusted even if
    # downstream tools write zero findings.
    actual_branch = _detect_git_branch(req.case.repo.repo_path)
    actual_commit = _detect_git_commit(req.case.repo.repo_path)

    # Record obvious mismatches immediately (still non-fatal).
    if req.case.branch and actual_branch and req.case.branch != actual_branch:
        case_warnings.append(
            f"case_context_branch_mismatch: expected={req.case.branch} actual={actual_branch}"
        )
    if req.case.branch and not actual_branch:
        case_warnings.append(
            f"case_context_branch_unknown: expected={req.case.branch} actual=None"
        )
    if req.case.commit and actual_commit and req.case.commit != actual_commit:
        case_warnings.append(
            f"case_context_commit_mismatch: expected={req.case.commit} actual={actual_commit}"
        )
    if req.case.commit and not actual_commit:
        case_warnings.append(
            f"case_context_commit_unknown: expected={req.case.commit} actual=None"
        )

    tool_runs_manifest: Dict[str, Any] = {}
    overall = 0

    for scanner in scanners:
        if req.invocation_mode == "benchmark":
            print("\n----------------------------------------")
            print(f"▶ {scanner}")

        extra_args: Dict[str, Any] = {}

        # Tool-specific args
        if scanner == "sonar":
            extra_args = _sonar_extra_args(repo_id=req.repo_id, sonar_project_key=req.sonar_project_key)
            print(f"  Sonar project key : {extra_args.get('project-key')}")

        if scanner == "aikido":
            # Prefer the captured case context branch (stable for the whole run).
            if actual_branch:
                extra_args = _merge_dicts(extra_args, {"branch": actual_branch})

        if scanner == "aikido" and req.aikido_git_ref:
            extra_args = _merge_dicts(extra_args, {"git-ref": req.aikido_git_ref})

        # Suite output rooting
        if bundle is not None:
            extra_args = _merge_dicts(extra_args, {"output-root": str(bundle.tool_runs_dir / scanner)})
            if scanner == "aikido":
                # Ensure Aikido writes to the same repo folder name for analysis.
                extra_args = _merge_dicts(extra_args, {"repo-name": req.case.runs_repo_name})

        cmd = build_scan_command(
            scanner,
            repo_url=req.case.repo.repo_url,
            repo_path=req.case.repo.repo_path,
            extra_args=extra_args,
            python_executable=req.python_executable,
        )

        tool_started = _now_iso()
        code = _run_one(cmd, dry_run=req.dry_run, quiet=req.quiet)
        tool_finished = _now_iso()

        if code != 0:
            overall = code

        # Record run info (best-effort) when using suites
        if bundle is not None:
            tool_out_root = bundle.tool_runs_dir / scanner

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
                        case_warnings.append(
                            f"repo_dir_suspicious:{scanner}:repo_dir_points_into_output_root:{srd}"
                        )
            except Exception:
                pass

            if run_dir:
                try:
                    _write_run_json(
                        run_dir,
                        suite_id=bundle.bundle_id,
                        case_id=bundle.target,
                        tool=scanner,
                        repo_name=req.case.runs_repo_name,
                        exit_code=code,
                        command=" ".join(cmd),
                        started=tool_started,
                        finished=tool_finished,
                    )
                except Exception as e:
                    case_warnings.append(f"write_run_json_failed:{scanner}:{run_dir}: {e}")

            run_json_path = str(run_dir / "run.json") if run_dir else None

            tool_runs_manifest[scanner] = {
                "exit_code": code,
                "command": " ".join(cmd),
                "started": tool_started,
                "finished": tool_finished,
                "output_root": str(tool_out_root),
                "run_root": str(run_root_dir) if run_root_dir else None,
                "repo_dir": str(scanned_repo_dir) if scanned_repo_dir else None,
                "run_id": run_dir.name if run_dir else None,
                "run_dir": str(run_dir) if run_dir else None,
                "run_json": run_json_path,
                "metadata": metadata,
            }

    # Backfill scanned repo context from tool metadata for runs where the CLI did not receive --repo-path.
    # This is critical for GT marker extraction and context diagnostics.
    case_repo_path = req.case.repo.repo_path
    case_repo_commit = actual_commit
    case_repo_branch = actual_branch

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
            from tools.core import get_git_commit as _get_git_commit, get_git_branch as _get_git_branch
            _p = _Path(case_repo_path)
            if not case_repo_commit:
                case_repo_commit = _get_git_commit(_p)
            if not case_repo_branch:
                case_repo_branch = _get_git_branch(_p)
        except Exception:
            pass

    analysis_summary: Optional[Dict[str, Any]] = None

    # -------------------------------------------------------------------
    # Write a *pre-analysis* case manifest so analysis stages (diagnostics +
    # GT marker scoring) can read case.json reliably.
    #
    # Previously, case.json was only written at the very end of run_tools(),
    # which meant the diagnostics_case_context stage would see "missing_case_json"
    # even though the pipeline was in suite mode.
    # -------------------------------------------------------------------
    manifest: Optional[Dict[str, Any]] = None
    if bundle is not None:
        manifest = {
            "suite": {"id": bundle.bundle_id, "suite_dir": str(bundle.suite_dir)},
            "case": {
                "id": bundle.target,
                "case_dir": str(bundle.case_dir),
                # Expected context comes from the CaseSpec (often micro-suites).
                "expected_branch": req.case.branch,
                "expected_commit": req.case.commit,
                "track": str(case_track) if case_track else None,
                "tags": dict(req.case.tags or {}),
            },
            "repo": {
                "label": req.case.label,
                "repo_url": req.case.repo.repo_url,
                # Prefer the scanned checkout path from tool metadata if available.
                "repo_path": case_repo_path,
                "runs_repo_name": req.case.runs_repo_name,
                "git_branch": case_repo_branch,
                "git_commit": case_repo_commit,
            },
            "invocation": {
                "mode": req.invocation_mode,
                "argv": list(req.argv) if req.argv else None,
                "python": req.python_executable,
                "skip_analysis": bool(req.skip_analysis),
                "environment": _runtime_environment(),
            },
            "timestamps": {"started": started, "finished": None},
            # Keep both for auditability
            "scanners_requested": list(scanners_requested),
            "scanners_used": list(scanners),
            "tool_runs": tool_runs_manifest,
            "analysis": None,
            "warnings": list(case_warnings),
            "errors": [],
        }

        # Write pre-analysis manifest (best-effort; never break scans)
        try:
            _write_json(bundle.case_json_path, manifest)
        except Exception as e:
            case_warnings.append(f"write_case_json_failed:pre_analysis:{e}")

    # Auto-analysis (only makes sense when bundling)
    if bundle is not None and req.invocation_mode == "benchmark" and not req.skip_analysis:
        print("\n----------------------------------------")
        print("▶ analysis suite")

        from pipeline.analysis.run_discovery import find_latest_normalized_json

        available_tools: List[str] = []
        for tool in scanners:
            try:
                find_latest_normalized_json(runs_dir=bundle.tool_runs_dir, tool=tool, repo_name=req.case.runs_repo_name)
                available_tools.append(tool)
            except FileNotFoundError:
                msg = f"missing_normalized_json:{tool}"
                case_warnings.append(msg)
                print(f"  ⚠️  missing normalized JSON for {tool}; skipping it in analysis")

        if available_tools:
            from pipeline.analysis.analyze_suite import run_suite

            analysis_summary = run_suite(
                repo_name=req.case.runs_repo_name,
                tools=available_tools,
                runs_dir=bundle.tool_runs_dir,
                out_dir=bundle.analysis_dir,
                tolerance=int(req.tolerance),
                mode=str(req.analysis_filter),
                formats=["json", "csv"],
            )
            print(f"  ✅ analysis complete: {bundle.analysis_dir}")
        else:
            print("  ⚠️  no tool outputs found; skipping analysis")

    finished = _now_iso()

    # Write final case manifest + suite summary
    if bundle is not None:
        if manifest is None:
            # Should not happen, but keep a safe fallback.
            manifest = {
                "suite": {"id": bundle.bundle_id, "suite_dir": str(bundle.suite_dir)},
                "case": {"id": bundle.target, "case_dir": str(bundle.case_dir)},
                "repo": {"label": req.case.label, "repo_url": req.case.repo.repo_url, "repo_path": case_repo_path},
                "invocation": {"mode": req.invocation_mode, "argv": list(req.argv) if req.argv else None},
                "timestamps": {"started": started, "finished": finished},
                "scanners_requested": list(scanners_requested),
                "scanners_used": list(scanners),
                "tool_runs": tool_runs_manifest,
                "analysis": analysis_summary,
                "warnings": list(case_warnings),
                "errors": [],
            }

        manifest["analysis"] = analysis_summary
        manifest.setdefault("timestamps", {})
        manifest["timestamps"]["finished"] = finished
        manifest["warnings"] = list(case_warnings)

        _write_json(bundle.case_json_path, manifest)
        update_suite_artifacts(bundle, manifest)

        print("\n📦 Case complete")
        print(f"  Suite id : {bundle.bundle_id}")
        print(f"  Suite dir: {bundle.suite_dir}")
        print(f"  Case dir : {bundle.case_dir}")
        print(f"  Tool runs: {bundle.tool_runs_dir}")
        print(f"  Analysis : {bundle.analysis_dir if not req.skip_analysis else '(skipped)'}")
        print(f"  Manifest : {bundle.case_json_path}")
        print(f"  Summary  : {bundle.suite_summary_path}")

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
