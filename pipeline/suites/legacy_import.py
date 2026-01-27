from __future__ import annotations

"""pipeline.suites.legacy_import

Deterministically import legacy run outputs into the canonical suite layout.

Goal
----
Older versions of the pipeline (and one-off scripts) wrote tool outputs under:

  runs/<tool>/<repo_name>/<run_id>/...

The current architecture anchors all artifacts under a suite:

  runs/suites/<suite_id>/cases/<case_id>/tool_runs/<tool>/<run_id>/...

This module provides a *single* compatibility boundary: convert legacy output
folders into the suite/case layout so the rest of the system can remain
suite-first.

Design constraints
------------------
- Non-interactive (CI safe): never prompt
- Deterministic: only uses explicit inputs + filesystem contents
- Best-effort IO: prefer warnings over hard failure, but fail when nothing can
  be imported
"""

import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

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
from sast_benchmark.io.fs import read_json, write_json_atomic


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hardlink_or_copy(src: Path, dst: Path, *, link_mode: str) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if link_mode == "hardlink":
        try:
            os.link(src, dst)
            return
        except Exception:
            # Fall back to copy
            pass
    shutil.copy2(src, dst)


def _copy_tree(src: Path, dst: Path, *, link_mode: str) -> None:
    """Recursively copy a directory tree.

    Uses hardlinks when link_mode == "hardlink" and supported.
    """

    if not src.exists() or not src.is_dir():
        raise FileNotFoundError(f"Source run dir not found: {src}")

    if dst.exists():
        raise FileExistsError(f"Destination run dir already exists: {dst}")

    for root, dirs, files in os.walk(src):
        rel = Path(root).relative_to(src)
        out_dir = dst / rel
        out_dir.mkdir(parents=True, exist_ok=True)

        for d in dirs:
            (out_dir / d).mkdir(parents=True, exist_ok=True)

        for fname in files:
            s = Path(root) / fname
            t = out_dir / fname
            # Do not preserve symlinks as symlinks; resolve to file contents.
            if s.is_symlink():
                try:
                    s = s.resolve()
                except Exception:
                    pass
            _hardlink_or_copy(s, t, link_mode=link_mode)


def _ensure_canonical_aliases(run_dir: Path, repo_name: str, *, link_mode: str) -> None:
    """Ensure suite-style canonical artifact names exist.

    Suite mode tools typically write:
      - normalized.json
      - raw.json or raw.sarif

    Legacy mode tools typically write:
      - <repo_name>.normalized.json
      - <repo_name>.json or <repo_name>.sarif

    Analysis supports both, but creating canonical aliases makes suites more
    uniform and reduces special-case handling elsewhere.
    """

    # normalized.json
    norm = run_dir / "normalized.json"
    legacy_norm = run_dir / f"{repo_name}.normalized.json"
    if not norm.exists() and legacy_norm.exists():
        _hardlink_or_copy(legacy_norm, norm, link_mode=link_mode)

    # raw
    raw_json = run_dir / "raw.json"
    raw_sarif = run_dir / "raw.sarif"
    legacy_json = run_dir / f"{repo_name}.json"
    legacy_sarif = run_dir / f"{repo_name}.sarif"

    if not raw_sarif.exists() and legacy_sarif.exists():
        _hardlink_or_copy(legacy_sarif, raw_sarif, link_mode=link_mode)
    if not raw_json.exists() and legacy_json.exists():
        _hardlink_or_copy(legacy_json, raw_json, link_mode=link_mode)


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

    write_json_atomic(run_dir / "run.json", data)


@dataclass(frozen=True)
class ImportResult:
    suite_id: str
    suite_dir: Path
    case_id: str
    case_dir: Path
    imported_tools: List[str]
    missing_tools: List[str]
    warnings: List[str]
    import_manifest_path: Path


def import_legacy_repo_to_suite(
    *,
    suite_root: Path,
    suite_id: Optional[str],
    case_id: str,
    runs_dir: Path,
    runs_repo_name: str,
    tools: Sequence[str],
    import_run_id: str = "latest",
    link_mode: str = "copy",
    repo_label: Optional[str] = None,
    repo_url: Optional[str] = None,
    repo_path: Optional[str] = None,
    track: Optional[str] = None,
    argv: Optional[Sequence[str]] = None,
    python_executable: Optional[str] = None,
) -> ImportResult:
    """Import legacy tool outputs for one repo into a suite.

    Parameters
    ----------
    suite_root:
        Base directory for suites (usually runs/suites)
    suite_id:
        Optional suite id; if None, a new timestamp id is generated
    case_id:
        Case folder name inside the suite
    runs_dir:
        Base directory containing legacy outputs (usually runs/)
    runs_repo_name:
        Repo folder name under legacy runs/<tool>/<repo_name>/...
    tools:
        Tools to import (e.g., ["semgrep", "snyk", "sonar"])
    import_run_id:
        "latest" or an explicit run_id directory name
    link_mode:
        "copy" (default) or "hardlink" when supported

    Returns
    -------
    ImportResult
    """

    sid = str(suite_id).strip() if suite_id else new_suite_id()

    suite_paths: SuitePaths = get_suite_paths(
        case_id=str(case_id), suite_id=sid, suite_root=suite_root
    )
    ensure_suite_dirs(suite_paths)
    update_latest_pointer(suite_paths)

    warnings: List[str] = []
    imported: List[str] = []
    missing: List[str] = []

    tool_runs_manifest: Dict[str, Any] = {}

    # Best-effort repo context captured from the first available tool metadata.
    case_repo_url = repo_url
    case_repo_path = repo_path
    case_git_branch: Optional[str] = None
    case_git_commit: Optional[str] = None

    mappings: Dict[str, Any] = {}

    for tool in tools:
        tool_dir = Path(runs_dir) / str(tool)
        if not tool_dir.exists() or not tool_dir.is_dir():
            missing.append(str(tool))
            warnings.append(f"legacy_tool_dir_missing:{tool}:{tool_dir}")
            continue

        repo_dir = discover_repo_dir(tool_dir, prefer=runs_repo_name)
        if repo_dir is None:
            missing.append(str(tool))
            warnings.append(f"legacy_repo_dir_not_found:{tool}:prefer={runs_repo_name}")
            continue

        if import_run_id and str(import_run_id).strip().lower() != "latest":
            candidate = repo_dir / str(import_run_id).strip()
            run_dir = candidate if candidate.exists() and candidate.is_dir() else None
            if run_dir is None:
                missing.append(str(tool))
                warnings.append(f"legacy_run_id_not_found:{tool}:{candidate}")
                continue
        else:
            run_dir = discover_latest_run_dir(repo_dir)
            if run_dir is None:
                missing.append(str(tool))
                warnings.append(f"legacy_latest_run_not_found:{tool}:{repo_dir}")
                continue

        # Destination: suite case tool_runs/<tool>/<run_id>/...
        dest_tool_root = suite_paths.tool_runs_dir / str(tool)
        dest_tool_root.mkdir(parents=True, exist_ok=True)
        dest_run_dir = dest_tool_root / run_dir.name

        try:
            _copy_tree(run_dir, dest_run_dir, link_mode=link_mode)
        except Exception as e:
            missing.append(str(tool))
            warnings.append(f"legacy_copy_failed:{tool}:{run_dir} -> {dest_run_dir}: {e}")
            continue

        # Add canonical aliases (normalized.json/raw.json) when missing.
        try:
            _ensure_canonical_aliases(dest_run_dir, runs_repo_name, link_mode=link_mode)
        except Exception as e:
            warnings.append(f"legacy_aliases_failed:{tool}:{dest_run_dir}: {e}")

        # Load metadata if present.
        meta_path = dest_run_dir / "metadata.json"
        metadata: Optional[Dict[str, Any]] = None
        if meta_path.exists() and meta_path.is_file():
            try:
                metadata = read_json(meta_path)
            except Exception as e:
                warnings.append(f"legacy_metadata_read_failed:{tool}:{meta_path}: {e}")

        # Backfill repo context.
        if isinstance(metadata, dict):
            case_repo_url = case_repo_url or (metadata.get("repo_url") or None)
            case_repo_path = case_repo_path or (
                metadata.get("repo_path") or metadata.get("repo_local_path") or None
            )
            case_git_branch = case_git_branch or (metadata.get("repo_branch") or None)
            case_git_commit = case_git_commit or (metadata.get("repo_commit") or None)

        # Write run.json (best-effort).
        exit_code = 0
        command = ""
        started = None
        finished = None
        if isinstance(metadata, dict):
            try:
                exit_code = int(metadata.get("exit_code") or 0)
            except Exception:
                exit_code = 0
            command = str(metadata.get("command") or "")
            ts = metadata.get("timestamp")
            if isinstance(ts, str) and ts:
                started = ts
                finished = ts

        try:
            _write_run_json(
                dest_run_dir,
                suite_id=sid,
                case_id=str(case_id),
                tool=str(tool),
                repo_name=runs_repo_name,
                exit_code=exit_code,
                command=command,
                started=started,
                finished=finished,
            )
        except Exception as e:
            warnings.append(f"legacy_write_run_json_failed:{tool}:{dest_run_dir}: {e}")

        tool_runs_manifest[str(tool)] = {
            "exit_code": exit_code,
            "command": command,
            "started": started,
            "finished": finished,
            "output_root": str(dest_tool_root),
            "run_root": str(dest_tool_root),
            "repo_dir": str(case_repo_path) if case_repo_path else None,
            "run_id": dest_run_dir.name,
            "run_dir": str(dest_run_dir),
            "run_json": str(dest_run_dir / "run.json"),
            "metadata": metadata,
            "imported_from": str(run_dir),
        }

        imported.append(str(tool))
        mappings[str(tool)] = {
            "src": str(run_dir),
            "dst": str(dest_run_dir),
            "run_id": str(dest_run_dir.name),
        }

    if not imported:
        raise SystemExit(
            "No legacy outputs were imported. "
            "Check --runs-dir/--runs-repo-name and confirm runs/<tool>/<repo>/<run_id>/ exists."
        )

    # Write case.json and suite-level indexes.
    started = _now_iso()
    finished = _now_iso()
    manifest = write_case_manifest(
        paths=suite_paths,
        invocation_mode="import",
        argv=list(argv) if argv else None,
        python_executable=str(python_executable) if python_executable else None,
        skip_analysis=True,
        repo_label=str(repo_label or runs_repo_name),
        repo_url=str(case_repo_url) if case_repo_url else None,
        repo_path=str(case_repo_path) if case_repo_path else None,
        runs_repo_name=str(runs_repo_name),
        expected_branch=None,
        expected_commit=None,
        track=str(track) if track else None,
        tags={"imported_from_legacy": True},
        git_branch=str(case_git_branch) if case_git_branch else None,
        git_commit=str(case_git_commit) if case_git_commit else None,
        started=started,
        finished=finished,
        scanners_requested=list(tools),
        scanners_used=list(imported),
        tool_runs=tool_runs_manifest,
        analysis=None,
        warnings=warnings,
        errors=[],
    )

    update_suite_artifacts(suite_paths, manifest)

    # Import manifest for traceability.
    import_dir = suite_paths.suite_dir / "import"
    import_dir.mkdir(parents=True, exist_ok=True)
    import_manifest_path = import_dir / "legacy_import.json"
    payload: Dict[str, Any] = {
        "timestamp": finished,
        "suite_id": sid,
        "case_id": str(case_id),
        "suite_dir": str(suite_paths.suite_dir),
        "case_dir": str(suite_paths.case_dir),
        "runs_dir": str(Path(runs_dir).resolve()),
        "runs_repo_name": str(runs_repo_name),
        "tools_requested": list(tools),
        "tools_imported": list(imported),
        "missing_tools": list(missing),
        "import_run_id": str(import_run_id),
        "link_mode": str(link_mode),
        "tool_mappings": mappings,
        "warnings": list(warnings),
    }
    try:
        write_json_atomic(import_manifest_path, payload)
    except Exception:
        pass

    return ImportResult(
        suite_id=sid,
        suite_dir=suite_paths.suite_dir,
        case_id=str(case_id),
        case_dir=suite_paths.case_dir,
        imported_tools=imported,
        missing_tools=missing,
        warnings=warnings,
        import_manifest_path=import_manifest_path,
    )
