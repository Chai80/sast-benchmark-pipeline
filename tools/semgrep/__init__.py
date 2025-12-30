"""tools/semgrep

Semgrep scanner package (Option B).

`tools/scan_semgrep.py` remains the stable script entrypoint used by the pipeline.
This package contains the implementation: runner + normalizer.
"""

from __future__ import annotations

from typing import Tuple, Dict, Any

from tools.core import (
    acquire_repo,
    build_run_metadata,
    which_or_raise,
    write_json,
)

from .runner import SEMGREP_FALLBACKS, prepare_run_paths, run_semgrep, semgrep_version, RunPaths
from .normalize import normalize_semgrep_results


def execute(
    *,
    repo_url: str | None,
    repo_path: str | None,
    repos_dir: str,
    output_root: str,
    config: str,
    timeout_seconds: int,
) -> Tuple[RunPaths, Dict[str, Any]]:
    repo = acquire_repo(repo_url=repo_url, repo_path=repo_path, repos_dir=repos_dir)

    semgrep_bin = which_or_raise("semgrep", fallbacks=SEMGREP_FALLBACKS)

    run_id, paths = prepare_run_paths(output_root, repo.repo_name)

    exit_code, elapsed, command_str = run_semgrep(
        semgrep_bin=semgrep_bin,
        repo_path=repo.repo_path,
        config=config,
        output_path=paths.raw_results,
        timeout_seconds=timeout_seconds,
    )

    meta = build_run_metadata(
        scanner="semgrep",
        scanner_version=semgrep_version(semgrep_bin),
        repo=repo,
        run_id=run_id,
        command_str=command_str,
        scan_time_seconds=elapsed,
        exit_code=exit_code,
        extra={"semgrep_config": config},
    )
    write_json(paths.metadata, meta)

    normalize_semgrep_results(
        repo_path=repo.repo_path,
        raw_results_path=paths.raw_results,
        metadata=meta,
        normalized_path=paths.normalized,
    )

    return paths, meta
