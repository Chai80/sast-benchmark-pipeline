#!/usr/bin/env python3
"""tools/scan_sonar.py

SonarCloud pipeline script for the sast-benchmark-pipeline.

This file is intentionally kept as a thin orchestrator:
  - parse CLI args
  - prepare repo + run directory
  - run sonar-scanner (optional)
  - fetch issues via SonarCloud REST API
  - write raw.json + metadata.json
  - call the normalizer to write normalized.json
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

from normalize_common import write_json
from run_utils import (
    clone_repo,
    create_run_dir,
    get_commit_author_info,
    get_git_commit,
    get_repo_name,
)

from sonar.api import (
    fetch_all_issues_for_project,
    validate_sonarcloud_credentials,
    wait_for_ce_success,
)
from sonar.normalize import normalize_sonar_results
from sonar.types import SonarConfig


SONAR_HOST_DEFAULT = "https://sonarcloud.io"

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")


@dataclass
class RunPaths:
    run_dir: Path
    log: Path
    raw_results: Path
    normalized: Path
    metadata: Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run SonarCloud scan on a repo and save JSON + metadata + normalized output."
    )
    p.add_argument("--repo-url", required=True)
    p.add_argument("--output-root", default="runs/sonar")
    p.add_argument("--project-key", default=None)
    p.add_argument("--java-binaries", default="")
    p.add_argument("--skip-scan", action="store_true")
    return p.parse_args()


def get_sonar_token() -> str:
    token = os.getenv("SONAR_TOKEN")
    if not token:
        print("ERROR: SONAR_TOKEN is not set.", file=sys.stderr)
        sys.exit(1)
    return token


def get_sonar_config() -> SonarConfig:
    host = os.environ.get("SONAR_HOST", SONAR_HOST_DEFAULT)
    org = os.environ.get("SONAR_ORG")
    token = get_sonar_token()
    if not org:
        print("ERROR: SONAR_ORG is not set.", file=sys.stderr)
        sys.exit(1)
    return SonarConfig(host=host, org=org, token=token)


def prepare_repo(repo_url: str, repos_root: Path = Path("repos")) -> Tuple[Path, str]:
    repo_path = clone_repo(repo_url, repos_root)
    repo_name = get_repo_name(repo_url)
    return repo_path, repo_name


def prepare_run_paths(output_root: str, repo_name: str) -> Tuple[str, RunPaths]:
    base = Path(output_root) / repo_name
    run_id, run_dir = create_run_dir(base)
    return run_id, RunPaths(
        run_dir=run_dir,
        log=run_dir / f"{repo_name}_sonar_scan.log",
        raw_results=run_dir / f"{repo_name}.json",
        normalized=run_dir / f"{repo_name}.normalized.json",
        metadata=run_dir / "metadata.json",
    )


def get_scanner_version() -> str:
    try:
        out = subprocess.check_output(
            ["sonar-scanner", "-v"],
            text=True,
            stderr=subprocess.STDOUT,
        )
        return out.strip()
    except Exception:
        return "unknown"


def run_sonar_scan(
    *,
    repo_path: Path,
    project_key: str,
    cfg: SonarConfig,
    java_binaries: str,
    log_path: Path,
) -> Tuple[int, float, List[str]]:
    cmd = [
        "sonar-scanner",
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


def build_run_metadata(
    *,
    cfg: SonarConfig,
    repo_path: Path,
    repo_name: str,
    repo_url: str,
    project_key: str,
    run_id: str,
    issues: List[Dict[str, Any]],
    scan_time: Optional[float],
    status: str,
    paths: RunPaths,
    command_str: Optional[str],
    exit_code: Optional[int],
) -> Dict[str, Any]:
    scanner_version = get_scanner_version()
    commit = get_git_commit(repo_path)
    author_info = get_commit_author_info(repo_path, commit)

    return {
        "scanner": "sonar",
        "scanner_kind": "sonar-scanner-cli",
        "scanner_version": scanner_version,
        "host": cfg.host,
        "organization": cfg.org,
        "project_key": project_key,
        "repo_name": repo_name,
        "repo_url": repo_url,
        "repo_local_path": str(repo_path),
        "repo_commit": commit,
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "scan_time_seconds": scan_time,
        "issues_count": len(issues),
        "status": status,
        "log_path": str(paths.log),
        "command": command_str,
        "exit_code": exit_code,
        **author_info,
    }


def main() -> None:
    args = parse_args()
    cfg = get_sonar_config()

    print(f"Using Sonar host: {cfg.host}")
    print(f"Using organization: {cfg.org}")

    validate_sonarcloud_credentials(cfg)
    print(f"✅ SonarCloud credentials OK. Organization '{cfg.org}' is accessible.")

    repo_path, repo_name = prepare_repo(args.repo_url)
    project_key = args.project_key or f"{cfg.org}_{repo_name}"
    print(f"Sonar project key: {project_key}")

    run_id, paths = prepare_run_paths(args.output_root, repo_name)

    scan_time: Optional[float] = None
    status = "skipped" if args.skip_scan else "success"
    command_str: Optional[str] = None
    exit_code: Optional[int] = None

    if not args.skip_scan:
        rc, elapsed, cmd = run_sonar_scan(
            repo_path=repo_path,
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

    write_json(paths.raw_results, build_issues_payload(
        project_key=project_key,
        cfg=cfg,
        repo_name=repo_name,
        issues=issues,
        run_id=run_id,
        scan_time=scan_time,
    ))
    print("📄 Issues JSON saved to:", paths.raw_results)

    metadata = build_run_metadata(
        cfg=cfg,
        repo_path=repo_path,
        repo_name=repo_name,
        repo_url=args.repo_url,
        project_key=project_key,
        run_id=run_id,
        issues=issues,
        scan_time=scan_time,
        status=status,
        paths=paths,
        command_str=command_str,
        exit_code=exit_code,
    )
    write_json(paths.metadata, metadata)
    print("📄 Metadata saved to:", paths.metadata)

    normalize_sonar_results(
        repo_path=repo_path,
        raw_results_path=paths.raw_results,
        metadata=metadata,
        normalized_path=paths.normalized,
        cfg=cfg,
    )
    print("📄 Normalized JSON saved to:", paths.normalized)


if __name__ == "__main__":
    main()
