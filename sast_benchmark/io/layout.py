"""sast_benchmark.io.layout

Canonical filesystem layout utilities.

This module centralizes:

* "suite mode" detection (v2 suite/case layout)
* legacy (v1) repo/<run_id> layout compatibility
* per-run artifact filenames (raw, normalized, metadata, logs)
* run discovery helpers (latest run, latest normalized.json)

The goal is to ensure that tools, analysis, and export code do **not**
re-implement their own layout heuristics.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence, Tuple, Union

from .run_dir import create_run_dir_compat


# Current:  YYYYMMDDNNHHMMSS (16 digits)
# Legacy:   YYYYMMDDNN       (10 digits)
RUN_ID_RE = re.compile(r"^\d{10}(\d{6})?$")


def is_suite_mode(output_root: Union[str, Path]) -> bool:
    """Heuristic: are we writing into a suite/case tool directory?

    In suite layout, tool output roots look like:

      runs/suites/<suite_id>/cases/<case_id>/tool_runs/<tool>

    Historically, some older runs used ``scans`` instead of ``tool_runs``.
    """
    p = Path(output_root)
    return p.parent.name in {"tool_runs", "scans"}


@dataclass(frozen=True)
class RunPaths:
    """Canonical artifact paths for one tool run."""

    run_dir: Path
    raw_results: Path
    normalized: Path
    metadata: Path
    log: Optional[Path] = None
    logs_dir: Optional[Path] = None

    # Backwards-compatible aliases
    @property
    def raw_sarif(self) -> Path:
        return self.raw_results


def prepare_run_paths(
    output_root: Union[str, Path],
    repo_name: str,
    *,
    raw_extension: str,
    suite_raw_basename: str = "raw",
    suite_normalized_name: str = "normalized.json",
    metadata_name: str = "metadata.json",
    suite_logs_dirname: str = "logs",
    suite_log_filename: Optional[str] = None,
    legacy_log_filename: Optional[str] = None,
) -> Tuple[str, RunPaths]:
    """Prepare per-run output paths (v2 suite/case or v1 legacy).

    Parameters
    ----------
    output_root:
        Tool output folder. Examples:
        - legacy: "runs/semgrep" (tool will write runs/semgrep/<repo>/<run_id>/...)
        - suite:  "runs/suites/<suite_id>/cases/<case_id>/tool_runs/semgrep"
    repo_name:
        Repo name used in legacy filenames.
    raw_extension:
        File extension including the dot: ".json" or ".sarif".
    suite_log_filename:
        If set, create logs dir and set RunPaths.log under it.
    legacy_log_filename:
        Optional filename for legacy mode. Can include "{repo_name}".

    Returns
    -------
    (run_id, RunPaths)
    """
    ext = (raw_extension or "").strip()
    if not ext.startswith("."):
        ext = f".{ext}" if ext else ".json"

    out_root = Path(output_root)
    suite_mode = is_suite_mode(out_root)

    if suite_mode:
        run_id, run_dir = create_run_dir_compat(out_root)
        raw = run_dir / f"{suite_raw_basename}{ext}"
        norm = run_dir / suite_normalized_name
        meta = run_dir / metadata_name

        logs_dir: Optional[Path] = None
        log_path: Optional[Path] = None
        if suite_log_filename:
            logs_dir = run_dir / suite_logs_dirname
            logs_dir.mkdir(parents=True, exist_ok=True)
            log_path = logs_dir / suite_log_filename

        return run_id, RunPaths(
            run_dir=run_dir,
            raw_results=raw,
            normalized=norm,
            metadata=meta,
            log=log_path,
            logs_dir=logs_dir,
        )

    # legacy: output_root/<repo_name>/<run_id>/...
    run_id, run_dir = create_run_dir_compat(out_root / repo_name)
    raw = run_dir / f"{repo_name}{ext}"
    norm = run_dir / f"{repo_name}.normalized.json"
    meta = run_dir / metadata_name

    log_path = None
    if legacy_log_filename:
        fname = legacy_log_filename.format(repo_name=repo_name)
        log_path = run_dir / fname

    return run_id, RunPaths(
        run_dir=run_dir,
        raw_results=raw,
        normalized=norm,
        metadata=meta,
        log=log_path,
        logs_dir=None,
    )


def discover_repo_dir(
    output_root: Path, prefer: Optional[str] = None
) -> Optional[Path]:
    """Discover the per-tool *run root* directory inside a case.

    Supports two layouts:

    v2 (preferred):
      <output_root>/<run_id>/...

    v1 (legacy):
      <output_root>/<repo_name>/<run_id>/...
    """
    if not output_root.exists() or not output_root.is_dir():
        return None

    # v2: output_root contains run_id directories directly.
    run_dirs = [
        d for d in output_root.iterdir() if d.is_dir() and RUN_ID_RE.match(d.name)
    ]
    if run_dirs:
        return output_root

    # v1: output_root contains repo folder(s); prefer an exact match if provided.
    if prefer:
        p = output_root / prefer
        if p.exists() and p.is_dir():
            return p

    dirs = [d for d in output_root.iterdir() if d.is_dir()]
    if len(dirs) == 1:
        return dirs[0]

    # If multiple, try to find a case-insensitive match
    if prefer:
        for d in dirs:
            if d.name.lower() == prefer.lower():
                return d

    return None


def discover_latest_run_dir(repo_dir: Path) -> Optional[Path]:
    """Return the latest run directory under repo_dir."""
    if not repo_dir.exists() or not repo_dir.is_dir():
        return None
    run_dirs = [d for d in repo_dir.iterdir() if d.is_dir() and RUN_ID_RE.match(d.name)]
    if not run_dirs:
        return None
    return max(run_dirs, key=lambda p: p.name)


def find_latest_run_dir(*, runs_dir: Path, tool: str, repo_name: str) -> Path:
    """Find the latest run directory for tool+repo.

    Supports both layouts:

    v2:
      <runs_dir>/<tool>/<run_id>/...

    v1:
      <runs_dir>/<tool>/<repo_name>/<run_id>/...
    """
    runs_dir = Path(runs_dir)
    tool_dir = runs_dir / tool
    if not tool_dir.exists():
        raise FileNotFoundError(f"Tool directory not found: {tool_dir}")

    # v2: tool_dir has run_id folders directly
    run_dirs = [d for d in tool_dir.iterdir() if d.is_dir() and RUN_ID_RE.match(d.name)]
    if run_dirs:
        return max(run_dirs, key=lambda p: p.name)

    # v1: tool_dir/<repo_name>/<run_id>
    repo_dir = discover_repo_dir(tool_dir, prefer=repo_name)
    if repo_dir:
        run_dirs = [
            d for d in repo_dir.iterdir() if d.is_dir() and RUN_ID_RE.match(d.name)
        ]
        if run_dirs:
            return max(run_dirs, key=lambda p: p.name)

    raise FileNotFoundError(
        f"No run_id folders found for tool={tool!r} repo={repo_name!r} under {tool_dir}"
    )


def find_latest_normalized_json(*, runs_dir: Path, tool: str, repo_name: str) -> Path:
    """Find the latest normalized JSON for tool+repo."""
    run_dir = find_latest_run_dir(runs_dir=runs_dir, tool=tool, repo_name=repo_name)

    candidates: Sequence[Path] = (
        run_dir / "normalized.json",
        run_dir / f"{repo_name}.normalized.json",
        run_dir / f"{repo_name}.normalized.json".replace("-", "_"),
    )
    for p in candidates:
        if p.exists() and p.is_file():
            return p

    norm_files = sorted(run_dir.glob("*.normalized.json"))
    if norm_files:
        return norm_files[0]

    raise FileNotFoundError(f"Normalized JSON not found in: {run_dir}")
