"""pipeline.execution.record

Filesystem side effects for :mod:`pipeline.execution.run_case`.

Rule
----
Only this module should write to disk for case execution (manifests,
receipts, suite layout initialization, etc.).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from pipeline.suites.layout import (
    SuitePaths,
    discover_latest_run_dir,
    discover_repo_dir,
    ensure_suite_dirs,
    get_suite_paths,
    new_suite_id,
)
from pipeline.suites.manifests import (
    update_latest_pointer,
    update_suite_artifacts,
    write_case_manifest,
)
from sast_benchmark.gt.catalog import materialize_case_gt_catalog
from tools.io import write_json

from .model import RunCaseRequest, ToolExecution, now_iso


def _load_json_if_exists(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists() or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _capture_optional_benchmark_yaml(
    repo_path: Optional[str],
    case_dir: Path,
    *,
    warnings: Optional[List[str]] = None,
) -> None:
    """Materialize GT inputs into <case_dir>/gt for suite reproducibility.

    Best-effort: never blocks scans; errors are appended to warnings.
    """

    if not repo_path:
        return
    try:
        repo_root = Path(str(repo_path))
        if not repo_root.exists() or not repo_root.is_dir():
            return
        gt_dir = Path(case_dir) / "gt"
        materialize_case_gt_catalog(repo_root, gt_dir, warnings=warnings)
    except Exception as e:
        if warnings is not None:
            warnings.append(f"gt_materialize_failed: {e}")
        return


def init_suite_paths(
    req: RunCaseRequest, *, case_warnings: List[str]
) -> Optional[SuitePaths]:
    """Create/ensure suite layout and return SuitePaths (or None)."""

    if not req.use_suite:
        return None

    sid = str(req.suite_id) if req.suite_id else new_suite_id()
    suite_paths = get_suite_paths(
        case_id=req.case.case_id, suite_id=sid, suite_root=req.suite_root
    )
    ensure_suite_dirs(suite_paths)
    update_latest_pointer(suite_paths)

    # Optional: capture suite GT YAML into the case folder for reproducibility
    _capture_optional_benchmark_yaml(
        req.case.repo.repo_path, suite_paths.case_dir, warnings=case_warnings
    )

    return suite_paths


def write_config_receipt_json(
    run_dir: Path,
    *,
    suite_id: str,
    case_id: str,
    tool: str,
    repo_name: str,
    profile: str,
    command: str,
    exit_code: int,
    started: Optional[str] = None,
    finished: Optional[str] = None,
) -> None:
    """Write run_dir/config_receipt.json."""

    run_id = run_dir.name

    metadata_file = "metadata.json" if (run_dir / "metadata.json").exists() else None

    data: Dict[str, Any] = {
        "schema_version": 1,
        "tool": tool,
        "profile": profile,
        "suite_id": suite_id,
        "case_id": case_id,
        "run_id": run_id,
        "repo_name": repo_name,
        "recorded_at": now_iso(),
        "command": command,
        "started": started,
        "finished": finished,
        "exit_code": int(exit_code),
        "artifacts": {
            "metadata": metadata_file,
            "rules_inventory": None,
        },
        "notes": [
            "Records configuration intent (profile) for reproducible comparisons.",
            "Does not imply different scanners share identical rule implementations.",
        ],
    }

    write_json(run_dir / "config_receipt.json", data)


def write_run_json(
    run_dir: Path,
    *,
    suite_id: str,
    case_id: str,
    tool: str,
    repo_name: str,
    exit_code: int,
    command: str,
    profile: str = "default",
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
    raw_name = _pick_first(
        ["raw.sarif", "raw.json", f"{repo_name}.sarif", f"{repo_name}.json"]
    )
    metadata_name = _pick_first(["metadata.json"])
    config_receipt_name = _pick_first(["config_receipt.json"])
    logs_dir = run_dir / "logs"
    logs_dir_name = "logs" if logs_dir.exists() and logs_dir.is_dir() else None

    data: Dict[str, Any] = {
        "suite_id": suite_id,
        "case_id": case_id,
        "tool": tool,
        "profile": profile,
        "run_id": run_id,
        "started": started,
        "finished": finished,
        "exit_code": int(exit_code),
        "command": command,
        "artifacts": {
            "normalized": normalized_name,
            "raw": raw_name,
            "metadata": metadata_name,
            "config_receipt": config_receipt_name,
            "logs_dir": logs_dir_name,
        },
    }

    write_json(run_dir / "run.json", data)


def record_tool_run_manifest(
    *,
    scanner: str,
    suite_paths: SuitePaths,
    req: RunCaseRequest,
    execution: ToolExecution,
    case_warnings: List[str],
    tool_runs_manifest: Dict[str, Any],
) -> None:
    """Best-effort discovery of tool outputs + run.json writing."""

    tool_out_root = suite_paths.tool_runs_dir / scanner

    # Discover the tool run root (layout v2: <output_root>/<run_id>/... or v1: <output_root>/<repo>/<run_id>/...)
    run_root_dir = discover_repo_dir(tool_out_root, prefer=req.case.runs_repo_name)
    run_dir = discover_latest_run_dir(run_root_dir) if run_root_dir else None
    metadata = _load_json_if_exists(
        (run_dir / "metadata.json") if run_dir else Path("/nonexistent")
    )

    # Prefer the scanner-captured local checkout path for downstream analysis/GT extraction.
    scanned_repo_dir = None
    if isinstance(metadata, dict):
        scanned_repo_dir = metadata.get("repo_path") or metadata.get("repo_local_path")
    if not scanned_repo_dir:
        scanned_repo_dir = req.case.repo.repo_path

    # Defensive check: repo_dir should never point at the tool output root.
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

    config_receipt_path = None
    if run_dir:
        try:
            write_config_receipt_json(
                run_dir,
                suite_id=suite_paths.suite_id,
                case_id=suite_paths.case_id,
                tool=scanner,
                repo_name=req.case.runs_repo_name,
                profile=str(req.profile),
                exit_code=execution.exit_code,
                command=execution.command_str,
                started=execution.started,
                finished=execution.finished,
            )
            config_receipt_path = str(run_dir / "config_receipt.json")
        except Exception as e:
            case_warnings.append(
                f"write_config_receipt_failed:{scanner}:{run_dir}: {e}"
            )

        try:
            write_run_json(
                run_dir,
                suite_id=suite_paths.suite_id,
                case_id=suite_paths.case_id,
                tool=scanner,
                repo_name=req.case.runs_repo_name,
                exit_code=execution.exit_code,
                command=execution.command_str,
                profile=str(req.profile),
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
        "profile": str(req.profile),
        "config_receipt": config_receipt_path,
        "metadata": metadata,
    }


def write_case_manifest_file(
    *,
    paths: SuitePaths,
    invocation_mode: str,
    argv: Optional[Sequence[str]],
    python_executable: Optional[str],
    skip_analysis: bool,
    repo_label: str,
    repo_url: Optional[str],
    repo_path: Optional[str],
    runs_repo_name: str,
    expected_branch: Optional[str],
    expected_commit: Optional[str],
    track: Optional[str],
    tags: Mapping[str, Any],
    git_branch: Optional[str],
    git_commit: Optional[str],
    started: str,
    finished: Optional[str],
    scanners_requested: Sequence[str],
    scanners_used: Sequence[str],
    tool_runs: Mapping[str, Any],
    analysis: Optional[Mapping[str, Any]],
    warnings: Sequence[str],
    errors: Sequence[str],
) -> Dict[str, Any]:
    """Write case.json via pipeline.suites.manifests.write_case_manifest."""

    return write_case_manifest(
        paths=paths,
        invocation_mode=invocation_mode,
        argv=argv,
        python_executable=python_executable,
        skip_analysis=bool(skip_analysis),
        repo_label=repo_label,
        repo_url=repo_url,
        repo_path=repo_path,
        runs_repo_name=runs_repo_name,
        expected_branch=expected_branch,
        expected_commit=expected_commit,
        track=track,
        tags=dict(tags or {}),
        git_branch=git_branch,
        git_commit=git_commit,
        started=started,
        finished=finished,
        scanners_requested=list(scanners_requested),
        scanners_used=list(scanners_used),
        tool_runs=dict(tool_runs),
        analysis=dict(analysis) if analysis is not None else None,
        warnings=list(warnings or []),
        errors=list(errors or []),
    )


def update_suite_indexes(paths: SuitePaths, manifest: Mapping[str, Any]) -> None:
    """Update suite-level artifacts (best-effort)."""

    update_suite_artifacts(paths, dict(manifest))


def maybe_run_analysis(
    *,
    req: RunCaseRequest,
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

    from pipeline.analysis.io.discovery import find_latest_normalized_json

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

    # If this suite has an effective GT tolerance recorded (QA calibration),
    # prefer it to keep benchmark/analyze outputs deterministic.
    effective_gt_tolerance = int(getattr(req, "gt_tolerance", 0) or 0)
    try:
        from pipeline.analysis.io.gt_tolerance_policy import (
            resolve_effective_gt_tolerance,
        )

        pol = resolve_effective_gt_tolerance(
            suite_dir=suite_paths.suite_dir,
            requested=int(getattr(req, "gt_tolerance", 0) or 0),
        )

        effective_gt_tolerance = int(
            pol.get("effective_gt_tolerance") or effective_gt_tolerance
        )
        src = str(pol.get("source") or "")

        # Record only when the policy *changes* the effective value.
        if src in {"selection_json", "suite_json"} and effective_gt_tolerance != int(
            getattr(req, "gt_tolerance", 0) or 0
        ):
            msg = (
                f"gt_tolerance overridden by {src}: requested={int(getattr(req, 'gt_tolerance', 0) or 0)} "
                f"effective={effective_gt_tolerance}"
            )
            case_warnings.append(msg)
            print(f"  ℹ️  {msg}")

        for w in pol.get("warnings") or []:
            if str(w).strip():
                print(f"  ⚠️  {w}")
    except Exception:
        # Best-effort only.
        pass

    from pipeline.analysis.analyze_suite import run_suite

    analysis_summary = run_suite(
        repo_name=req.case.runs_repo_name,
        tools=available_tools,
        runs_dir=suite_paths.tool_runs_dir,
        out_dir=suite_paths.analysis_dir,
        tolerance=int(req.tolerance),
        gt_tolerance=int(effective_gt_tolerance),
        gt_source=str(req.gt_source),
        mode=str(req.analysis_filter),
        exclude_prefixes=req.exclude_prefixes,
        include_harness=bool(req.include_harness),
        formats=["json", "csv"],
    )
    print(f"  ✅ analysis complete: {suite_paths.analysis_dir}")
    return analysis_summary
