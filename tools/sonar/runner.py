"""tools/sonar/runner.py

SonarCloud scan orchestration.

This module contains the *implementation* for running SonarCloud scans in this
repo:

  repo -> (optional) sonar-scanner -> wait CE -> fetch issues -> write artifacts -> normalize

Why this exists
---------------

We keep tools/scan_sonar.py as a stable, thin CLI entrypoint (similar to
tools/scan_semgrep.py and tools/scan_snyk.py). The heavier implementation lives
here so:

* Sonar-specific complexity is contained in tools/sonar/
* tests can import and exercise execute() without subprocess CLI parsing
* the pipeline has one consistent mental model for scan entrypoints
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

from sast_benchmark.io.layout import RunPaths, prepare_run_paths as _prepare_run_paths

from tools.core import (
    ROOT_DIR,
    acquire_repo,
    build_run_metadata,
    run_cmd,
    which_or_raise,
    write_json,
)

from tools.sonar.api import (
    component_exists,
    fetch_all_issues_for_project,
    validate_sonarcloud_credentials,
    wait_for_ce_success,
)
from tools.sonar.normalize import normalize_sonar_results
from tools.sonar.types import SonarConfig


SONAR_HOST_DEFAULT = "https://sonarcloud.io"
SONAR_SCANNER_FALLBACKS = ["/opt/homebrew/bin/sonar-scanner", "/usr/local/bin/sonar-scanner"]


def _get_sonar_token() -> str:
    token = os.getenv("SONAR_TOKEN")
    if not token:
        raise SystemExit("ERROR: SONAR_TOKEN is not set.")
    return token


def _get_sonar_config() -> SonarConfig:
    host = os.environ.get("SONAR_HOST", SONAR_HOST_DEFAULT)
    org = os.environ.get("SONAR_ORG")
    token = _get_sonar_token()
    if not org:
        raise SystemExit("ERROR: SONAR_ORG is not set.")
    return SonarConfig(host=host, org=org, token=token)


def _prepare_paths(output_root: str, repo_name: str) -> Tuple[str, RunPaths]:
    """Prepare per-run output paths.

    Delegates to :func:`sast_benchmark.io.layout.prepare_run_paths` so the
    filesystem contract is owned by one module.
    """
    return _prepare_run_paths(
        output_root,
        repo_name,
        raw_extension=".json",
        suite_log_filename="sonar_scan.log",
        legacy_log_filename="{repo_name}_sonar_scan.log",
    )


def _scanner_version(sonar_bin: Optional[str]) -> str:
    """Best-effort sonar-scanner version string."""
    if not sonar_bin:
        # Skip-scan mode may not have the CLI installed; that's fine.
        return "unknown"
    try:
        res = run_cmd([sonar_bin, "-v"], print_stderr=False, print_stdout=False)
        out = (res.stdout or res.stderr).strip()
        return out or "unknown"
    except FileNotFoundError:
        return "unknown"


def _run_sonar_scanner(
    *,
    sonar_bin: str,
    repo_path: Path,
    project_key: str,
    cfg: SonarConfig,
    java_binaries: str,
    log_path: Path,
) -> Tuple[int, float, List[str]]:
    cmd: List[str] = [
        sonar_bin,
        f"-Dsonar.projectKey={project_key}",
        f"-Dsonar.organization={cfg.org}",
        f"-Dsonar.host.url={cfg.host}",
        "-Dsonar.sources=.",
    ]
    if java_binaries:
        cmd.append(f"-Dsonar.java.binaries={java_binaries}")

    env = dict(os.environ)
    env["SONAR_TOKEN"] = cfg.token

    t0 = time.time()
    with log_path.open("w", encoding="utf-8") as log_file:
        result = subprocess.run(
            cmd,
            cwd=repo_path,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )
    return result.returncode, time.time() - t0, cmd


def _build_issues_payload(
    *,
    project_key: str,
    cfg: SonarConfig,
    repo_name: str,
    issues: List[Dict[str, Any]],
    run_id: str,
    scan_time: Optional[float],
) -> Dict[str, Any]:
    return {
        "projectKey": project_key,
        "organization": cfg.org,
        "repo_name": repo_name,
        "scan_time_seconds": scan_time,
        "issue_count": len(issues),
        "issues": issues,
        "run_id": run_id,
        "generated_at": datetime.now().isoformat(),
    }


def _choose_project_key(*, repo_name: str, cfg: SonarConfig, project_key: Optional[str]) -> str:
    """Pick a project key.

    If a project_key is explicitly provided, use it.

    Otherwise, generate candidates based on repo_name and prefer reusing a key
    that already exists in the org (to avoid duplicates/private projects).
    """
    if project_key:
        return project_key

    # Prefer underscores to match SonarCloud UI import conventions.
    frag_underscore = re.sub(r"[^A-Za-z0-9_.:-]+", "_", repo_name.replace("-", "_"))
    frag_underscore = frag_underscore.strip("_") or repo_name.replace("-", "_")
    frag_dash = re.sub(r"[^A-Za-z0-9_.:-]+", "_", repo_name).strip("_") or repo_name

    candidates: List[str] = []
    for frag in (frag_underscore, frag_dash):
        key = f"{cfg.org}_{frag}"
        if key not in candidates:
            candidates.append(key)

    for cand in candidates:
        if component_exists(cfg, cand):
            return cand

    return candidates[0]


def execute(
    *,
    repo_url: Optional[str],
    repo_path: Optional[str],
    repos_dir: str = "repos",
    output_root: str = "runs/sonar",
    project_key: Optional[str] = None,
    java_binaries: str = "",
    skip_scan: bool = False,
) -> Tuple[RunPaths, Dict[str, Any]]:
    """Execute a SonarCloud scan and write raw + metadata + normalized outputs.

    Returns (RunPaths, metadata_dict).

    This is safe to import and call from tests and from tools/scan_sonar.py.
    """

    # Load .env once, at runtime (not import-time)
    load_dotenv(ROOT_DIR / ".env")

    cfg = _get_sonar_config()
    print(f"Using Sonar host: {cfg.host}")
    print(f"Using organization: {cfg.org}")

    validate_sonarcloud_credentials(cfg)
    print(f"✅ SonarCloud credentials OK. Organization '{cfg.org}' is accessible.")

    repo = acquire_repo(repo_url=repo_url, repo_path=repo_path, repos_dir=repos_dir)
    repo_name = repo.repo_name

    chosen_key = _choose_project_key(repo_name=repo_name, cfg=cfg, project_key=project_key)
    print(f"Sonar project key: {chosen_key}")

    run_id, paths = _prepare_paths(output_root, repo_name)

    scan_time: Optional[float] = None
    status = "skipped" if skip_scan else "success"
    command_str: str = ""
    exit_code: int = 0
    sonar_bin: Optional[str] = None

    if not skip_scan:
        sonar_bin = which_or_raise("sonar-scanner", fallbacks=SONAR_SCANNER_FALLBACKS)

        # prepare_run_paths already creates logs_dir in suite-mode, but keep a
        # defensive mkdir for legacy paths.
        log_path = paths.log or (paths.run_dir / "sonar_scan.log")
        log_path.parent.mkdir(parents=True, exist_ok=True)

        rc, elapsed, cmd = _run_sonar_scanner(
            sonar_bin=sonar_bin,
            repo_path=repo.repo_path,
            project_key=chosen_key,
            cfg=cfg,
            java_binaries=java_binaries,
            log_path=log_path,
        )
        scan_time = elapsed
        command_str = " ".join(cmd)
        exit_code = rc

        if rc != 0:
            status = "scan_failed"
            print(f"⚠️ sonar-scanner failed ({rc}). See log: {log_path}")
        else:
            print(f"✅ sonar-scanner finished in {elapsed:.2f}s. Log: {log_path}")
    else:
        print("⏭️ Skipping sonar-scanner run (per --skip-scan).")

    if status == "success":
        wait_for_ce_success(cfg, chosen_key)

    issues = fetch_all_issues_for_project(cfg, chosen_key)
    print(f"📥 Retrieved {len(issues)} issues from SonarCloud")

    write_json(
        paths.raw_results,
        _build_issues_payload(
            project_key=chosen_key,
            cfg=cfg,
            repo_name=repo_name,
            issues=issues,
            run_id=run_id,
            scan_time=scan_time,
        ),
    )

    metadata = build_run_metadata(
        scanner="sonar",
        scanner_version=_scanner_version(sonar_bin),
        repo=repo,
        run_id=run_id,
        command_str=command_str,
        scan_time_seconds=scan_time or 0.0,
        exit_code=exit_code,
        extra={
            "scanner_kind": "sonar-scanner-cli",
            "host": cfg.host,
            "organization": cfg.org,
            "project_key": chosen_key,
            "repo_local_path": str(repo.repo_path),
            "issues_count": len(issues),
            "status": status,
            "log_path": str(paths.log) if paths.log else "",
        },
    )
    write_json(paths.metadata, metadata)

    normalize_sonar_results(
        repo_path=repo.repo_path,
        raw_results_path=paths.raw_results,
        metadata=metadata,
        normalized_path=paths.normalized,
        cfg=cfg,
    )

    return paths, metadata

