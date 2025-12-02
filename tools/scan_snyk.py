#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

# Load .env from project root (one level up from tools/)
ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run Snyk Code on a repo and save JSON + metadata."
    )
    p.add_argument(
        "--repo-url",
        help=(
            "Git URL of the repo to scan "
            "(e.g. https://github.com/juice-shop/juice-shop.git)"
        ),
    )
    p.add_argument(
        "--output-root",
        default="runs/snyk",
        help="Root folder to store outputs (default: runs/snyk)",
    )
    p.add_argument(
        "--org",
        default=None,
        help="Optional Snyk org id/slug to use with --org.",
    )
    p.add_argument(
        "--severity-threshold",
        default=None,
        choices=["low", "medium", "high"],
        help="Optional Snyk severity threshold (low|medium|high).",
    )
    args = p.parse_args()
    if not args.repo_url:
        args.repo_url = input("Enter Git repo URL to scan: ").strip()
    return args


def get_repo_name(repo_url: str) -> str:
    last = repo_url.rstrip("/").split("/")[-1]
    return last[:-4] if last.endswith(".git") else last


def clone_repo(repo_url: str, base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    name = get_repo_name(repo_url)
    path = base / name

    if not path.exists():
        print(f"📥 Cloning {name} from {repo_url} ...")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(path)],
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git clone failed with code {result.returncode}")
    else:
        print(f"✅ Repo already exists, reusing: {path}")

    return path


def get_git_commit(path: Path) -> str:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            text=True,
        )
        return out.strip()
    except Exception:
        return "unknown"


def get_commit_author_info(repo_path: Path, commit: str) -> dict:
    """Return author name/email/date for the commit we scanned."""
    try:
        out = subprocess.check_output(
            [
                "git",
                "-C",
                str(repo_path),
                "show",
                "-s",
                "--format=%an%n%ae%n%aI",
                commit,
            ],
            text=True,
        )
        lines = out.splitlines()
        return {
            "commit_author_name": lines[0] if len(lines) > 0 else None,
            "commit_author_email": lines[1] if len(lines) > 1 else None,
            "commit_date": lines[2] if len(lines) > 2 else None,
        }
    except subprocess.CalledProcessError:
        return {
            "commit_author_name": None,
            "commit_author_email": None,
            "commit_date": None,
        }


def create_run_dir(output_root: Path) -> tuple[str, Path]:
    today = datetime.now().strftime("%Y%m%d")
    output_root.mkdir(parents=True, exist_ok=True)

    existing = [
        d.name
        for d in output_root.iterdir()
        if d.is_dir() and d.name.startswith(today)
    ]
    if not existing:
        idx = 1
    else:
        last = max(existing)
        try:
            last_idx = int(last[-2:])
        except ValueError:
            last_idx = len(existing)
        idx = last_idx + 1

    run_id = f"{today}{idx:02d}"
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    print("📂 Using run directory:", run_dir)
    return run_id, run_dir


def get_snyk_version() -> str:
    try:
        out = subprocess.check_output(["snyk", "--version"], text=True)
        return out.strip()
    except Exception:
        return "unknown"


def normalize_snyk_results(
    repo_path: Path,
    raw_results_path: Path,
    metadata: dict,
    normalized_path: Path,
) -> None:
    """
    Convert Snyk Code JSON (SARIF-like) into the common normalized schema.

    Assumes `snyk code test` JSON looks like:
      { "runs": [ { "results": [ ... ] } ] }

    Schema v1.1: every finding includes its own `metadata` block so that
    each finding can stand on its own when exported to a table.
    """
    # Build common metadata once so we can reuse it at the top level and
    # inside every finding.
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
        "tool": "snyk",
        "tool_version": metadata.get("scanner_version"),
        "target_repo": target_repo,
        "scan": scan_info,
    }

    if not raw_results_path.exists():
        # Snyk didn't create a JSON file (or we pointed to the wrong location)
        normalized = {
            "schema_version": "1.1",
            "tool": "snyk",
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

    runs = data.get("runs", [])
    findings: list[dict] = []

    for run in runs:
        for res in run.get("results", []):
            rule_id = res.get("ruleId")
            level = res.get("level")  # error|warning|note
            message = (res.get("message") or {}).get("text")
            locations = res.get("locations") or []
            if locations:
                physical = (locations[0].get("physicalLocation") or {})
                artifact = physical.get("artifactLocation") or {}
                region = physical.get("region") or {}
                file_path = artifact.get("uri")
                line = region.get("startLine")
                end_line = region.get("endLine", line)
            else:
                file_path = None
                line = None
                end_line = None

            # Try to read the line of code for context
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
                    pass

            props = res.get("properties") or {}
            cwe = props.get("cwe")
            if isinstance(cwe, list):
                cwe_id = cwe[0] if cwe else None
            else:
                cwe_id = cwe

            # Map SARIF level to normalized severity
            if level == "error":
                severity = "HIGH"
            elif level == "warning":
                severity = "MEDIUM"
            elif level in ("note", "info"):
                severity = "LOW"
            else:
                severity = None

            finding = {
                "metadata": per_finding_metadata,
                "finding_id": f"snyk:{rule_id}:{file_path}:{line}",
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
        "tool": "snyk",
        "tool_version": metadata.get("scanner_version"),
        "target_repo": target_repo,
        "scan": scan_info,
        "findings": findings,
    }

    with normalized_path.open("w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2)


def main() -> None:
    args = parse_args()

    # 0. Make sure SNYK_TOKEN is set (from .env or environment)
    snyk_token = os.getenv("SNYK_TOKEN")
    if not snyk_token:
        print(
            "ERROR: SNYK_TOKEN is not set.\n"
            "Add it to your .env or export it in your shell before running.",
            file=sys.stderr,
        )
        sys.exit(1)

    # 1. Clone repo
    repo_base = Path("repos")
    repo_path = clone_repo(args.repo_url, repo_base)
    repo_name = get_repo_name(args.repo_url)

    # 2. Prepare output paths
    output_root = Path(args.output_root)
    run_id, run_dir = create_run_dir(output_root)

    # Important: use absolute path so Snyk writes to the pipeline folder,
    # not inside repos/<repo_name> when cwd=repo_path
    run_dir = run_dir.resolve()
    raw_results_path = run_dir / f"{repo_name}.json"
    normalized_path = run_dir / f"{repo_name}.normalized.json"
    metadata_path = run_dir / "metadata.json"

    # 3. Build Snyk command (SAST via Snyk Code)
    cmd = ["snyk", "code", "test", "--json-file-output", str(raw_results_path)]
    if args.org:
        cmd.extend(["--org", args.org])
    if args.severity_threshold:
        cmd.extend(["--severity-threshold", args.severity_threshold])

    print(f"\n🔍 Running Snyk Code on {repo_name} ...")
    print("Command:", " ".join(cmd))

    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=repo_path,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError:
        print(
            "ERROR: 'snyk' CLI not found on PATH. "
            "Install it with 'npm install -g snyk' and make sure 'snyk --version' works.",
            file=sys.stderr,
        )
        sys.exit(1)
    elapsed = time.time() - t0

    # Exit codes: 0 = no vulns, 1 = vulns found, 2/3 = failure
    if proc.returncode in (0, 1):
        print(
            f"✅ Snyk Code finished in {elapsed:.2f}s "
            f"(exit code {proc.returncode})"
        )
    else:
        print(f"⚠️ Snyk Code failed with exit code {proc.returncode}")
        print(proc.stderr[:2000])
    print("Raw JSON path (expected):", raw_results_path)

    # 4. Build metadata
    commit = get_git_commit(repo_path)
    author_info = get_commit_author_info(repo_path, commit)
    scanner_version = get_snyk_version()

    metadata = {
        "scanner": "snyk",
        "scanner_version": scanner_version,
        "repo_name": repo_name,
        "repo_url": args.repo_url,
        "repo_commit": commit,
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "command": " ".join(cmd),
        "scan_time_seconds": elapsed,
        "exit_code": proc.returncode,
        **author_info,
    }
    with metadata_path.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("📄 Metadata saved to:", metadata_path)

    # 5. Normalized JSON
    normalize_snyk_results(repo_path, raw_results_path, metadata, normalized_path)
    print("📄 Normalized JSON saved to:", normalized_path)


if __name__ == "__main__":
    main()
