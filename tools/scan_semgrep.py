#!/usr/bin/env python3
"""
scan_semgrep.py

Run Semgrep on a repo and save:
  - raw JSON results
  - metadata.json
  - normalized findings JSON (schema v1.1)

Output layout:

  runs/semgrep/<repo_name>/<run_id>/
    ├── <repo_name>.json
    ├── <repo_name>.normalized.json
    └── metadata.json
"""

import argparse
import json
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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


# ---------- CLI & basic helpers ----------


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for the Semgrep scan."""
    p = argparse.ArgumentParser(
        description="Run Semgrep on a repo and save JSON + metadata + normalized output."
    )
    p.add_argument(
        "--repo-url",
        help="Git URL of the repo to scan "
        "(e.g. https://github.com/juice-shop/juice-shop.git)",
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


def get_semgrep_version() -> str:
    """Return the installed Semgrep CLI version, or 'unknown' if it fails."""
    try:
        out = subprocess.check_output(["semgrep", "--version"], text=True)
        return out.strip()
    except Exception:
        return "unknown"


def write_json(path: Path, data: Dict[str, Any]) -> None:
    """Write a JSON file with pretty-printing."""
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ---------- Running Semgrep ----------


def run_semgrep_scan(
    repo_path: Path,
    repo_name: str,
    results_path: Path,
    config: str,
) -> Tuple[int, float, str]:
    """
    Run Semgrep on the given repo.

    Returns:
      (exit_code, elapsed_seconds, command_string)
    """
    cmd = [
        "semgrep",
        "--config",
        config,
        "--json",
        "--quiet",
        "--output",
        str(results_path),
        str(repo_path),
    ]

    print(f"\n🔍 Running Semgrep on {repo_name} ...")
    print("Command:", " ".join(cmd))

    t0 = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - t0

    if result.returncode != 0:
        print(f"⚠️ Semgrep failed with code {result.returncode}")
        print(result.stderr[:2000])
    else:
        print(f"✅ Semgrep finished in {elapsed:.2f}s")
        print("JSON saved to:", results_path)

    return result.returncode, elapsed, " ".join(cmd)


def build_run_metadata(
    repo_path: Path,
    repo_name: str,
    repo_url: str,
    run_id: str,
    exit_code: int,
    elapsed: float,
    command_str: str,
) -> Dict[str, Any]:
    """Collect commit + scanner info into a single metadata dict."""
    commit = get_git_commit(repo_path)
    author_info = get_commit_author_info(repo_path, commit)
    scanner_version = get_semgrep_version()

    return {
        "scanner": "semgrep",
        "scanner_version": scanner_version,
        "repo_name": repo_name,
        "repo_url": repo_url,
        "repo_commit": commit,
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "command": command_str,
        "scan_time_seconds": elapsed,
        "exit_code": exit_code,
        **author_info,
    }


# ---------- Normalization helpers ----------


def map_semgrep_severity(severity_raw: str) -> Optional[str]:
    """Map Semgrep severity strings into HIGH / MEDIUM / LOW."""
    s = (severity_raw or "").upper()
    if s in ("ERROR", "CRITICAL", "HIGH"):
        return "HIGH"
    if s in ("WARNING", "MEDIUM"):
        return "MEDIUM"
    if s in ("INFO", "LOW"):
        return "LOW"
    return None


def extract_location_and_line_content(
    res: Dict[str, Any],
    repo_path: Path,
) -> Tuple[Optional[str], Optional[int], Optional[int], Optional[str]]:
    """Extract file path, line range, and source line from a Semgrep result."""
    file_path = res.get("path")
    start = res.get("start") or {}
    end = res.get("end") or {}

    line = start.get("line")
    end_line = end.get("line", line)

    line_content: Optional[str] = None
    if file_path and line:
        file_abs = repo_path / file_path
        try:
            lines = file_abs.read_text(encoding="utf-8", errors="replace").splitlines()
            if 1 <= line <= len(lines):
                line_content = lines[line - 1].rstrip("\n")
        except OSError:
            # If we can't read the file for some reason, just skip line_content
            pass

    return file_path, line, end_line, line_content


def normalize_semgrep_results(
    repo_path: Path,
    raw_results_path: Path,
    metadata: Dict[str, Any],
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
        "scan_time_seconds": metadata.get("scan_time_seconds"),
        "exit_code": metadata.get("exit_code"),
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
            "run_metadata": metadata,
            "findings": [],
        }
        write_json(normalized_path, normalized)
        return

    with raw_results_path.open(encoding="utf-8") as f:
        data = json.load(f)

    semgrep_results = data.get("results") or []
    findings: List[Dict[str, Any]] = []

    for res in semgrep_results:
        rule_id = res.get("check_id")

        file_path, line, end_line, line_content = (
            extract_location_and_line_content(res, repo_path)
        )

        extra = res.get("extra") or {}
        message = extra.get("message")
        severity_raw = extra.get("severity") or ""
        meta = extra.get("metadata") or {}

        cwe = meta.get("cwe")
        if isinstance(cwe, list):
            cwe_id = cwe[0] if cwe else None
        else:
            cwe_id = cwe

        severity = map_semgrep_severity(severity_raw)

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
        "run_metadata": metadata,
        "findings": findings,
    }

    write_json(normalized_path, normalized)


# ---------- Top-level pipeline ----------


def main() -> None:
    args = parse_args()

    # 1. Clone repo (shared helper)
    repo_base = Path("repos")
    repo_path = clone_repo(args.repo_url, repo_base)
    repo_name = get_repo_name(args.repo_url)

    # 2. Prepare output paths (shared run_dir helper)
    #    This creates: runs/semgrep/<repo_name>/<run_id>/
    output_root = Path(args.output_root) / repo_name
    run_id, run_dir = create_run_dir(output_root)

    results_path = run_dir / f"{repo_name}.json"
    normalized_path = run_dir / f"{repo_name}.normalized.json"
    metadata_path = run_dir / "metadata.json"

    # 3. Run Semgrep
    exit_code, elapsed, command_str = run_semgrep_scan(
        repo_path=repo_path,
        repo_name=repo_name,
        results_path=results_path,
        config=args.config,
    )

    # 4. Build and save metadata
    metadata = build_run_metadata(
        repo_path=repo_path,
        repo_name=repo_name,
        repo_url=args.repo_url,
        run_id=run_id,
        exit_code=exit_code,
        elapsed=elapsed,
        command_str=command_str,
    )
    write_json(metadata_path, metadata)
    print("📄 Metadata saved to:", metadata_path)

    # 5. Normalized JSON
    normalize_semgrep_results(
        repo_path=repo_path,
        raw_results_path=results_path,
        metadata=metadata,
        normalized_path=normalized_path,
    )
    print("📄 Normalized JSON saved to:", normalized_path)


if __name__ == "__main__":
    main()
