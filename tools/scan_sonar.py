#!/usr/bin/env python3
"""tools/scan_sonar.py

SonarCloud pipeline script for the sast-benchmark-pipeline.

Preferred invocation (package):
  python -m tools.scan_sonar --repo-url https://github.com/juice-shop/juice-shop

Outputs:
  runs/sonar/<repo_name>/<run_id>/
    - <repo_name>.json              (raw issues payload)
    - metadata.json
    - <repo_name>.normalized.json

Design goals:
- Thin orchestrator: repo -> (optional) sonar-scanner -> API issues -> normalize
- Use tools.core for shared plumbing (repo acquisition, run dirs, JSON IO, metadata)
- Avoid import-time side effects (no load_dotenv at import time)
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Minimal bootstrap so this file can be executed directly while using
# clean package imports.
#
# IMPORTANT: This must run BEFORE importing local packages like `sast_benchmark`
# when the script is invoked as: `python tools/scan_sonar.py ...`
# ---------------------------------------------------------------------------
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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
    fetch_all_issues_for_project,
    validate_sonarcloud_credentials,
    wait_for_ce_success,
    component_exists,
)
from tools.sonar.normalize import normalize_sonar_results
from tools.sonar.types import SonarConfig


SONAR_HOST_DEFAULT = "https://sonarcloud.io"
SONAR_SCANNER_FALLBACKS = ["/opt/homebrew/bin/sonar-scanner", "/usr/local/bin/sonar-scanner"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run SonarCloud scan on a repo and save JSON + metadata + normalized output."
    )
    p.add_argument("--repo-url", required=False, help="Git repo URL to scan.")
    p.add_argument("--repo-path", required=False, help="Local repo path to scan (skip clone).")
    p.add_argument("--repos-dir", default="repos", help="Repos base dir. Default: repos.")
    p.add_argument("--output-root", default="runs/sonar", help="Output root. Default: runs/sonar.")
    p.add_argument("--project-key", default=None, help="Optional SonarCloud project key override.")
    p.add_argument("--java-binaries", default="", help="Optional sonar.java.binaries path(s).")
    p.add_argument("--skip-scan", action="store_true", help="Skip sonar-scanner execution and only fetch issues.")
    args = p.parse_args()

    if args.repo_url and args.repo_path:
        raise SystemExit("Provide only one of --repo-url or --repo-path.")

    if not args.repo_url and not args.repo_path:
        raise SystemExit("Provide --repo-url or --repo-path.")

    return args


# ---------------------------------------------------------------------------
# Sonar config (env)
# ---------------------------------------------------------------------------

def get_sonar_token() -> str:
    token = os.getenv("SONAR_TOKEN")
    if not token:
        raise SystemExit("ERROR: SONAR_TOKEN is not set.")
    return token


def get_sonar_config() -> SonarConfig:
    host = os.environ.get("SONAR_HOST", SONAR_HOST_DEFAULT)
    org = os.environ.get("SONAR_ORG")
    token = get_sonar_token()
    if not org:
        raise SystemExit("ERROR: SONAR_ORG is not set.")
    return SonarConfig(host=host, org=org, token=token)


# ---------------------------------------------------------------------------
# Run directory layout
# ---------------------------------------------------------------------------

def prepare_run_paths(output_root: str, repo_name: str) -> Tuple[str, RunPaths]:
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


# ---------------------------------------------------------------------------
# Sonar-scanner execution
# ---------------------------------------------------------------------------

def get_scanner_version(sonar_bin: Optional[str]) -> str:
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


def run_sonar_scan(
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


# ---------------------------------------------------------------------------
# Raw payload + metadata
# ---------------------------------------------------------------------------

def build_issues_payload(
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    # Load .env once, at runtime (not import-time)
    load_dotenv(ROOT_DIR / ".env")

    args = parse_args()
    cfg = get_sonar_config()

    print(f"Using Sonar host: {cfg.host}")
    print(f"Using organization: {cfg.org}")

    validate_sonarcloud_credentials(cfg)
    print(f"✅ SonarCloud credentials OK. Organization '{cfg.org}' is accessible.")

    repo = acquire_repo(repo_url=args.repo_url, repo_path=args.repo_path, repos_dir=args.repos_dir)
    repo_name = repo.repo_name

    project_key = args.project_key
    if not project_key:
        # Prefer underscores to match SonarCloud UI import conventions and avoid duplicate projects.
        frag_underscore = re.sub(r"[^A-Za-z0-9_.:-]+", "_", repo_name.replace("-", "_"))
        frag_underscore = frag_underscore.strip("_") or repo_name.replace("-", "_")
        frag_dash = re.sub(r"[^A-Za-z0-9_.:-]+", "_", repo_name).strip("_") or repo_name
        candidates: List[str] = []
        for frag in (frag_underscore, frag_dash):
            key = f"{cfg.org}_{frag}"
            if key not in candidates:
                candidates.append(key)

        # Reuse an existing SonarCloud project key when possible (avoids creating duplicates / private projects).
        for cand in candidates:
            if component_exists(cfg, cand):
                project_key = cand
                break
        if not project_key:
            project_key = candidates[0]
    print(f"Sonar project key: {project_key}")

    run_id, paths = prepare_run_paths(args.output_root, repo_name)

    scan_time: Optional[float] = None
    status = "skipped" if args.skip_scan else "success"
    command_str: str = ""
    exit_code: int = 0

    sonar_bin: Optional[str] = None

    if not args.skip_scan:
        sonar_bin = which_or_raise("sonar-scanner", fallbacks=SONAR_SCANNER_FALLBACKS)

        paths.log.parent.mkdir(parents=True, exist_ok=True)

        rc, elapsed, cmd = run_sonar_scan(
            sonar_bin=sonar_bin,
            repo_path=repo.repo_path,
            project_key=project_key,
            cfg=cfg,
            java_binaries=args.java_binaries,
            log_path=paths.log,
        )
        scan_time = elapsed
        command_str = " ".join(cmd)
        exit_code = rc

        if rc != 0:
            status = "scan_failed"
            print(f"⚠️ sonar-scanner failed ({rc}). See log: {paths.log}")
        else:
            print(f"✅ sonar-scanner finished in {elapsed:.2f}s. Log: {paths.log}")
    else:
        print("⏭️ Skipping sonar-scanner run (per --skip-scan).")

    if status == "success":
        wait_for_ce_success(cfg, project_key)

    issues = fetch_all_issues_for_project(cfg, project_key)
    print(f"📥 Retrieved {len(issues)} issues from SonarCloud")

    write_json(
        paths.raw_results,
        build_issues_payload(
            project_key=project_key,
            cfg=cfg,
            repo_name=repo_name,
            issues=issues,
            run_id=run_id,
            scan_time=scan_time,
        ),
    )
    print("📄 Issues JSON saved to:", paths.raw_results)

    metadata = build_run_metadata(
        scanner="sonar",
        scanner_version=get_scanner_version(sonar_bin),
        repo=repo,
        run_id=run_id,
        command_str=command_str,
        scan_time_seconds=scan_time or 0.0,
        exit_code=exit_code,
        extra={
            "scanner_kind": "sonar-scanner-cli",
            "host": cfg.host,
            "organization": cfg.org,
            "project_key": project_key,
            "repo_local_path": str(repo.repo_path),
            "issues_count": len(issues),
            "status": status,
            "log_path": str(paths.log),
        },
    )
    write_json(paths.metadata, metadata)
    print("📄 Metadata saved to:", paths.metadata)

    normalize_sonar_results(
        repo_path=repo.repo_path,
        raw_results_path=paths.raw_results,
        metadata=metadata,
        normalized_path=paths.normalized,
        cfg=cfg,
    )
    print("📄 Normalized JSON saved to:", paths.normalized)


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as e:
        print(f"❌ {e}", file=sys.stderr)
        raise SystemExit(127)
