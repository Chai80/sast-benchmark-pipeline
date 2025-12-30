"""tools/snyk

Snyk scanner package (Option B).

`tools/scan_snyk.py` remains the stable script entrypoint used by the pipeline.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from tools.core import (
    acquire_repo,
    build_run_metadata,
    which_or_raise,
    write_json,
)

from .runner import SNYK_BIN_FALLBACKS, prepare_run_paths, run_snyk_code_sarif, snyk_version, RunPaths
from .vendor_rules import load_snyk_vendor_owasp_2021_index
from .normalize import normalize_sarif


def execute(
    *,
    repo_url: str | None,
    repo_path: str | None,
    repos_dir: str,
    output_root: str,
) -> Tuple[RunPaths, Dict[str, Any]]:
    if not repo_url and not repo_path:
        raise SystemExit("Provide --repo-url or --repo-path.")

    repo = acquire_repo(repo_url=repo_url, repo_path=repo_path, repos_dir=repos_dir)
    snyk_bin = which_or_raise("snyk", fallbacks=SNYK_BIN_FALLBACKS)

    run_id, paths = prepare_run_paths(output_root, repo.repo_name)

    exit_code, elapsed, cmd_str = run_snyk_code_sarif(
        snyk_bin=snyk_bin,
        repo_path=repo.repo_path,
        out_sarif=paths.raw_sarif,
    )

    meta = build_run_metadata(
        scanner="snyk",
        scanner_version=snyk_version(snyk_bin),
        repo=repo,
        run_id=run_id,
        command_str=cmd_str,
        scan_time_seconds=elapsed,
        exit_code=exit_code,
    )
    write_json(paths.metadata, meta)

    vendor_idx = load_snyk_vendor_owasp_2021_index()
    normalize_sarif(
        repo_path=repo.repo_path,
        raw_sarif_path=paths.raw_sarif,
        metadata=meta,
        vendor_idx=vendor_idx,
        normalized_path=paths.normalized,
    )

    return paths, meta
