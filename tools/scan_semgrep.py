#!/usr/bin/env python3
"""
tools/scan_semgrep.py

Semgrep scanner wrapper for sast-benchmark-pipeline.

Outputs:
  runs/semgrep/<repo_name>/<run_id>/
    - <repo_name>.json
    - metadata.json
    - <repo_name>.normalized.json

Design goals:
- Match the normalized output shape used by scan_snyk/scan_sonar (schema v1.1)
- Reuse classification_resolver.py (CWE + OWASP 2017/2021)
- Be resilient to helper signature drift in run_utils.py
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# -------------------------
# Flexible imports (your repo runs tools/*.py as scripts)
# -------------------------

try:
    # Most common in your repo
    from run_utils import (
        clone_repo,
        create_run_dir,
        get_repo_name,
        get_git_commit,
        get_commit_author_info,
    )
except Exception:
    # Fallback if you use tools.run_utils
    from tools.run_utils import (  # type: ignore
        clone_repo,
        create_run_dir,
        get_repo_name,
        get_git_commit,
        get_commit_author_info,
    )

try:
    from classification_resolver import resolve_owasp_and_cwe
except Exception:
    from tools.classification_resolver import resolve_owasp_and_cwe  # type: ignore


ROOT_DIR = Path(__file__).resolve().parents[1]


# -------------------------
# Small utilities
# -------------------------

def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def find_semgrep_bin() -> str:
    """
    Find semgrep binary reliably across conda / brew / pipx.
    """
    semgrep_bin = shutil.which("semgrep")
    if semgrep_bin:
        return semgrep_bin

    # Common macOS fallbacks
    for candidate in ("/opt/homebrew/bin/semgrep", "/usr/local/bin/semgrep"):
        if Path(candidate).exists():
            return candidate

    raise FileNotFoundError(
        "Semgrep executable not found.\n"
        "Install with ONE of:\n"
        "  - pip install semgrep\n"
        "  - brew install semgrep\n"
        "  - pipx install semgrep\n"
        "Then ensure `semgrep` is on your PATH."
    )


def get_semgrep_version() -> str:
    try:
        semgrep_bin = find_semgrep_bin()
        out = subprocess.check_output([semgrep_bin, "--version"], text=True)
        return out.strip()
    except Exception:
        return "unknown"


def map_semgrep_severity(sev: Optional[str]) -> Optional[str]:
    """
    Normalize Semgrep severity to your common severity scale.
    Semgrep typical: ERROR, WARNING, INFO.
    """
    if not sev:
        return None
    s = str(sev).strip().upper()
    if s == "ERROR":
        return "HIGH"
    if s == "WARNING":
        return "MEDIUM"
    if s == "INFO":
        return "LOW"
    if s == "CRITICAL":
        return "HIGH"
    if s in {"HIGH", "MEDIUM", "LOW"}:
        return s
    return "MEDIUM"


def normalize_repo_relative_path(repo_path: Path, semgrep_path: Optional[str]) -> Optional[str]:
    """
    Semgrep sometimes returns absolute paths. Convert to repo-relative when possible.
    """
    if not semgrep_path:
        return None
    p = Path(semgrep_path)
    try:
        if p.is_absolute():
            return str(p.resolve().relative_to(repo_path.resolve()))
    except Exception:
        return semgrep_path
    return semgrep_path


def read_line_content(repo_path: Path, file_path: str, line_no: int) -> Optional[str]:
    """
    Read one line (1-indexed) from a file relative to repo_path.
    """
    try:
        abs_path = (repo_path / file_path).resolve()
        if not abs_path.exists():
            return None
        with abs_path.open("r", encoding="utf-8", errors="replace") as f:
            for i, ln in enumerate(f, start=1):
                if i == line_no:
                    return ln.rstrip("\n")
    except Exception:
        return None
    return None


def load_cwe_to_owasp_map() -> dict:
    """
    Load mappings/cwe_to_owasp_top10_mitre.json (same one you use elsewhere).
    Supports either wrapped {"_meta":..., "cwe_to_owasp": {...}} or direct dicts.
    """
    p = ROOT_DIR / "mappings" / "cwe_to_owasp_top10_mitre.json"
    if not p.exists():
        return {}
    try:
        data = read_json(p)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


# -------------------------
# CLI
# -------------------------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Run Semgrep scan and normalize results.")
    ap.add_argument("--repo-url", required=False, help="Git repo URL to scan.")
    ap.add_argument("--repo-path", required=False, help="Local repo path to scan (skip clone).")
    ap.add_argument("--config", default="auto", help="Semgrep config. Default: auto.")
    ap.add_argument("--output-root", default="runs/semgrep", help="Output root. Default: runs/semgrep.")
    ap.add_argument("--repos-dir", default="repos", help="Repos base dir. Default: repos.")
    ap.add_argument("--timeout-seconds", type=int, default=0, help="Semgrep timeout. 0 = no timeout.")
    ns = ap.parse_args()

    if not ns.repo_url and not ns.repo_path:
        ns.repo_url = input("Enter Git repo URL to scan: ").strip()

    if ns.repo_url and ns.repo_path:
        raise SystemExit("Provide only one of --repo-url or --repo-path.")

    return ns


# -------------------------
# Running Semgrep
# -------------------------

def run_semgrep(
    repo_path: Path,
    config: str,
    output_path: Path,
    timeout_seconds: int = 0,
) -> Tuple[int, float, str]:
    semgrep_bin = find_semgrep_bin()
    cmd = [semgrep_bin, "--json", "--config", config, "--output", str(output_path)]

    print(f"\n🔍 Running Semgrep on {repo_path.name} ...")
    print("Command:", " ".join(cmd))

    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_path),
            text=True,
            capture_output=True,
            timeout=timeout_seconds if timeout_seconds and timeout_seconds > 0 else None,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.time() - t0
        return 124, elapsed, " ".join(cmd)

    elapsed = time.time() - t0

    # Semgrep prints a lot of status text to stderr even on success — show it
    if proc.stderr:
        print(proc.stderr)

    return proc.returncode, elapsed, " ".join(cmd)


# -------------------------
# Normalize Semgrep JSON to your schema
# -------------------------

def normalize_semgrep_results(
    repo_path: Path,
    raw_results_path: Path,
    metadata: Dict[str, Any],
    normalized_path: Path,
) -> None:
    if not raw_results_path.exists():
        # If semgrep produced no output file, still emit a normalized shell.
        normalized = {
            "schema_version": "1.1",
            "tool": "semgrep",
            "tool_version": metadata.get("scanner_version"),
            "target_repo": {
                "name": metadata.get("repo_name"),
                "url": metadata.get("repo_url"),
                "commit": metadata.get("repo_commit"),
            },
            "scan": {
                "tool": "semgrep",
                "run_id": metadata.get("run_id"),
                "timestamp": metadata.get("timestamp"),
                "command": metadata.get("command"),
                "scan_time_seconds": metadata.get("scan_time_seconds"),
                "exit_code": metadata.get("exit_code"),
            },
            "run_metadata": metadata,
            "findings": [],
        }
        write_json(normalized_path, normalized)
        return

    raw = read_json(raw_results_path)
    results = raw.get("results") or []

    cwe_to_owasp_map = load_cwe_to_owasp_map()

    target_repo = {
        "name": metadata.get("repo_name"),
        "url": metadata.get("repo_url"),
        "commit": metadata.get("repo_commit"),
    }
    scan_info = {
        "tool": "semgrep",
        "run_id": metadata.get("run_id"),
        "timestamp": metadata.get("timestamp"),
        "command": metadata.get("command"),
        "scan_time_seconds": metadata.get("scan_time_seconds"),
        "exit_code": metadata.get("exit_code"),
    }
    per_finding_metadata = {
        "tool": "semgrep",
        "tool_version": metadata.get("scanner_version"),
        "target_repo": target_repo,
        "scan": scan_info,
    }

    findings: List[Dict[str, Any]] = []

    for res in results:
        rule_id = res.get("check_id")

        file_path = normalize_repo_relative_path(repo_path, res.get("path"))
        start = res.get("start") or {}
        end = res.get("end") or {}
        line = start.get("line")
        end_line = end.get("line", line)

        line_content = None
        if file_path and line:
            line_content = read_line_content(repo_path, file_path, int(line))

        extra = res.get("extra") or {}
        message = extra.get("message")
        severity_norm = map_semgrep_severity(extra.get("severity"))

        meta = extra.get("metadata") or {}
        semgrep_owasp_tags = _as_list(meta.get("owasp"))
        semgrep_cwe_candidates = _as_list(meta.get("cwe"))
        vuln_class_list = _as_list(meta.get("vulnerability_class"))
        vuln_class = str(vuln_class_list[0]) if vuln_class_list else None

        # Feed your shared resolver (same idea as Snyk)
        tags: List[str] = []
        tags += [str(x) for x in semgrep_owasp_tags if x is not None]
        tags += [str(x) for x in vuln_class_list if x is not None]
        tags += [str(x) for x in _as_list(meta.get("category")) if x is not None]
        tags += [str(x) for x in _as_list(meta.get("technology")) if x is not None]

        classification = resolve_owasp_and_cwe(
            tags=tags,
            cwe_candidates=semgrep_cwe_candidates,
            cwe_to_owasp_map=cwe_to_owasp_map,
            vendor_owasp_2021_codes=None,
            allow_2017_from_tags=True,
        )

        finding_id = f"semgrep:{rule_id}:{file_path}:{line}"

        findings.append(
            {
                "metadata": per_finding_metadata,
                "finding_id": finding_id,
                "rule_id": rule_id,
                "title": message,
                "severity": severity_norm,
                "file_path": file_path,
                "line_number": line,
                "end_line_number": end_line,
                "line_content": line_content,

                # important: match Snyk/Sonar normalized fields
                "cwe_id": classification.get("cwe_id"),
                "cwe_ids": classification.get("cwe_ids") or [],
                "vuln_class": vuln_class,
                "owasp_top_10_2017": classification.get("owasp_top_10_2017"),
                "owasp_top_10_2021": classification.get("owasp_top_10_2021"),

                "vendor": {"raw_result": res},
            }
        )

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


# -------------------------
# Helpers: run_dir creation tolerant to signature drift
# -------------------------

def create_run_dir_compat(output_root: Path) -> Tuple[str, Path]:
    """
    Your run_utils.create_run_dir() has drifted in signature/return shape.
    This wrapper makes it consistent.

    Accepts: output_root = runs/semgrep/<repo_name>
    Returns: (run_id, run_dir)
    """
    output_root = output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    # Try positional call first (works regardless of kw names)
    res = create_run_dir(output_root)

    # Common patterns:
    #  - (run_id, run_dir)
    #  - (run_dir, run_id)
    #  - run_dir only
    if isinstance(res, tuple) and len(res) == 2:
        a, b = res
        if isinstance(a, str) and isinstance(b, (str, Path)):
            run_id = a
            run_dir = Path(b)
            return run_id, run_dir
        if isinstance(a, Path) and isinstance(b, str):
            return b, a
        if isinstance(a, Path) and isinstance(b, Path):
            # pick name as run_id
            return b.name, b
        if isinstance(a, str) and isinstance(b, str):
            return a, Path(b)

    if isinstance(res, Path):
        return res.name, res

    if isinstance(res, str):
        # If function returns a run_dir path as string
        p = Path(res)
        return p.name, p

    # As a final fallback, create our own run folder
    run_id = datetime.now().strftime("%Y%m%d%H")
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_id, run_dir


# -------------------------
# Main
# -------------------------

def main() -> None:
    args = parse_args()

    # 1) Acquire repo
    repo_url = args.repo_url
    if args.repo_path:
        repo_path = Path(args.repo_path).resolve()
        repo_name = repo_path.name
    else:
        if not repo_url:
            raise SystemExit("Missing --repo-url (or provide --repo-path).")
        repos_dir = Path(args.repos_dir).resolve()
        repo_path = clone_repo(repo_url, repos_dir)
        repo_name = get_repo_name(repo_url)

    # 2) Create run directory
    output_root = Path(args.output_root).resolve() / repo_name
    run_id, run_dir = create_run_dir_compat(output_root)

    results_path = run_dir / f"{repo_name}.json"
    normalized_path = run_dir / f"{repo_name}.normalized.json"
    metadata_path = run_dir / "metadata.json"

    # 3) Run semgrep
    exit_code, elapsed, command_str = run_semgrep(
        repo_path=repo_path,
        config=args.config,
        output_path=results_path,
        timeout_seconds=args.timeout_seconds,
    )

    # 4) Metadata (IMPORTANT: your get_commit_author_info needs (repo_path, commit))
    commit = get_git_commit(repo_path)
    try:
        author_info = get_commit_author_info(repo_path, commit)
    except TypeError:
        # If your helper ever changes again, don't break scans
        author_info = {}

    metadata: Dict[str, Any] = {
        "scanner": "semgrep",
        "scanner_version": get_semgrep_version(),
        "repo_name": repo_name,
        "repo_url": repo_url,
        "repo_commit": commit,
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "command": command_str,
        "scan_time_seconds": elapsed,
        "exit_code": exit_code,
        **(author_info or {}),
    }

    write_json(metadata_path, metadata)
    print("📄 Raw JSON saved to:", results_path)
    print("📄 Metadata saved to:", metadata_path)

    # 5) Normalize
    normalize_semgrep_results(
        repo_path=repo_path,
        raw_results_path=results_path,
        metadata=metadata,
        normalized_path=normalized_path,
    )
    print("📄 Normalized JSON saved to:", normalized_path)

    # Important: let the wrapper decide what to print based on exit code.
    # We do not print "Scan finished with exit code ..." here.


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as e:
        # Make missing semgrep a clean error (not a giant traceback)
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(127)
