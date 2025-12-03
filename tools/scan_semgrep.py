#!/usr/bin/env python3
"""
scan_semgrep.py

Run Semgrep on a repo and save:
  - raw JSON results
  - metadata.json
  - normalized findings JSON (schema v1.1)
"""

import argparse
import json
import subprocess
import time
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root (one level up from tools/)
ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")

# Shared helpers used by all scanners
from run_utils import (
    get_repo_name,
    clone_repo,
    get_git_commit,
    get_commit_author_info,
    create_run_dir,
)


def parse_args() -> argparse.Namespace:
    """
    Parse CLI arguments for the Semgrep scan.
    """
    p = argparse.ArgumentParser(
        description="Run Semgrep on a repo and save JSON + metadata + normalized output."
    )
    p.add_argument(
        "--repo-url",
        help="Git URL of the repo to scan (e.g. https://github.com/juice-shop/juice-shop.git)",
    )
    p.add_argument(
        "--output-root",
        default="runs/semgrep",
        help="Root folder to store outputs (default: runs/semgrep)",
    )
    p.add_argument(
        "--config",
        default="p/security-audit",
        help="Semgrep config to use (default: p/security-audit)",
    )
    args = p.parse_args()
    if not args.repo_url:
        args.repo_url = input("Enter Git repo URL to scan: ").strip()
    return args


def normalize_semgrep_results(
    repo_path: Path,
    raw_results_path: Path,
    metadata: dict,
    normalized_path: Path,
) -> None:
    """
    Convert Semgrep JSON into the common normalized schema (schema v1.1).

    Semgrep `--json` output looks roughly like:
      {
        "results": [ { ... }, ... ],
        "errors": [ ... ],
        ...
      }
    """
    # Shared metadata blocks for top-level and per-finding metadata
    target_repo = {
        "name": metadata.get("repo_name"),
        "url": metadata.get("repo_url"),
        "commit": metadata.get("repo_commit"),
        "commit_author_name": metadata.get("commit_author_name"),
        "commit_author_email": metadata.get("commit_author_email"),
        "commit_date": metadata.get("commit_date"),
    }
    scan_info = {
        "run_id": metadata.get("run_id"),
        "scan_date": metadata.get("timestamp"),
        "command": metadata.get("command"),
        "raw_results_path": str(raw_results_path),
        "metadata_path": "metadata.json",
    }
    per_finding_metadata = {
        "tool": "semgrep",
        "tool_version": metadata.get("scanner_version"),
        "target_repo": target_repo,
        "scan": scan_info,
    }

    # If Semgrep never wrote a JSON file, emit an empty findings list
    if not raw_results_path.exists():
        normalized = {
            "schema_version": "1.1",
            "tool": "semgrep",
            "tool_version": metadata.get("scanner_version"),
            "target_repo": target_repo,
            "scan": scan_info,
            "findings": [],
        }
        with normalized_path.open("w", encoding="utf-8") as f:
            json.dump(normalized, f, indent=2)
        return

    with raw_results_path.open(encoding="utf-8") as f:
        data = json.load(f)

    semgrep_results = data.get("results") or []
    findings: list[dict] = []

    for res in semgrep_results:
        rule_id = res.get("check_id")
        file_path = res.get("path")
        start = res.get("start") or {}
        end = res.get("end") or {}

        line = start.get("line")
        end_line = end.get("line", line)

        extra = res.get("extra") or {}
        message = extra.get("message")
        severity_raw = (extra.get("severity") or "").upper()
        meta = extra.get("metadata") or {}

        cwe = meta.get("cwe")
        if isinstance(cwe, list):
            cwe_id = cwe[0] if cwe else None
        else:
            cwe_id = cwe

        # Map Semgrep severities to HIGH / MEDIUM / LOW
        if severity_raw in ("ERROR", "CRITICAL", "HIGH"):
            severity = "HIGH"
        elif severity_raw in ("WARNING", "MEDIUM"):
            severity = "MEDIUM"
        elif severity_raw in ("INFO", "LOW"):
            severity = "LOW"
        else:
            severity = None

        # Try to read the source line for context
        line_content = None
        if file_path and line:
            file_abs = repo_path / file_path
            try:
                lines = file_abs.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
                if 1 <= line <= len(lines):
                    line_content = lines[line - 1].rstrip("\n")
            except OSError:
                # If we can't read the file for some reason, just skip line_content
                pass

        finding = {
            "metadata": per_finding_metadata,
            "finding_id": f"semgrep:{rule_id}:{file_path}:{line}",
            "cwe_id": cwe_id,
            "rule_id": rule_id,
            "title": message,
            "severity": severity,
            "file_path": file_path,
            "line_number": line,
            "end_line_number": end_line,
            "line_content": line_content,
            "vendor": {
                "raw_result": res,
            },
        }
        findings.append(finding)

    normalized = {
        "schema_version": "1.1",
        "tool": "semgrep",
        "tool_version": metadata.get("scanner_version"),
        "target_repo": target_repo,
        "scan": scan_info,
        "findings": findings,
    }

    with normalized_path.open("w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2)


def main() -> None:
    args = parse_args()

    # 1. Clone repo (shared helper)
    repo_base = Path("repos")
    repo_path = clone_repo(args.repo_url, repo_base)
    repo_name = get_repo_name(args.repo_url)

    # 2. Prepare output paths (shared run_dir helper)
    output_root = Path(args.output_root)
    run_id, run_dir = create_run_dir(output_root)

    results_path = run_dir / f"{repo_name}.json"
    normalized_path = run_dir / f"{repo_name}.normalized.json"
    metadata_path = run_dir / "metadata.json"

    # 3. Run Semgrep
    print(f"\n🔍 Running Semgrep on {repo_name} ...")
    t0 = time.time()
    cmd = [
        "semgrep",
        "--config",
        args.config,
        "--json",
        "--quiet",
        "--output",
        str(results_path),
        str(repo_path),
    ]
    print("Command:", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - t0

    if result.returncode != 0:
        print(f"⚠️ Semgrep failed with code {result.returncode}")
        print(result.stderr[:2000])
    else:
        print(f"✅ Semgrep finished in {elapsed:.2f}s")
        print("JSON saved to:", results_path)

    # 4. Build metadata
    commit = get_git_commit(repo_path)
    author_info = get_commit_author_info(repo_path, commit)
    try:
        scanner_version = subprocess.check_output(
            ["semgrep", "--version"], text=True
        ).strip()
    except Exception:
        scanner_version = "unknown"

    metadata = {
        "scanner": "semgrep",
        "scanner_version": scanner_version,
        "repo_name": repo_name,
        "repo_url": args.repo_url,
        "repo_commit": commit,
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "command": " ".join(cmd),
        "scan_time_seconds": elapsed,
        "exit_code": result.returncode,
        **author_info,
    }
    with metadata_path.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("📄 Metadata saved to:", metadata_path)

    # 5. Normalized JSON
    normalize_semgrep_results(repo_path, results_path, metadata, normalized_path)
    print("📄 Normalized JSON saved to:", normalized_path)


if __name__ == "__main__":
    main()
