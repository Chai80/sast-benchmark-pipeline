#!/usr/bin/env python3
"""
tools/scan_semgrep.py

Semgrep scanner wrapper for sast-benchmark-pipeline.

Preferred invocation (package):
  python -m tools.scan_semgrep --repo-url https://github.com/juice-shop/juice-shop

Still supported (direct script):
  python tools/scan_semgrep.py --repo-url https://github.com/juice-shop/juice-shop

Outputs:
  runs/semgrep/<repo_name>/<run_id>/
    - <repo_name>.json
    - metadata.json
    - <repo_name>.normalized.json

Design goals:
- Thin orchestrator: acquire repo -> run semgrep -> write raw + metadata -> normalize
- No try/except import scaffolding; use the tools package API
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Minimal bootstrap so this file can be executed directly while using
# clean package imports (no try/except import scaffolding).
# ---------------------------------------------------------------------------
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.classification_resolver import resolve_owasp_and_cwe
from tools.core import (
    acquire_repo,
    build_run_metadata,
    create_run_dir_compat,
    load_cwe_to_owasp_map,
    normalize_repo_relative_path,
    read_json,
    read_line_content,
    run_cmd,
    which_or_raise,
    write_json,
)
from tools.normalize_common import (
    build_per_finding_metadata,
    build_scan_info,
    build_target_repo,
)
from tools.normalize_extractors import extract_cwe_candidates, extract_location


SEMGREP_FALLBACKS = ["/opt/homebrew/bin/semgrep", "/usr/local/bin/semgrep"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Run Semgrep scan and normalize results.")
    ap.add_argument("--repo-url", required=False, help="Git repo URL to scan.")
    ap.add_argument("--repo-path", required=False, help="Local repo path to scan (skip clone).")
    ap.add_argument("--config", default="auto", help="Semgrep config. Default: auto.")
    ap.add_argument("--output-root", default="runs/semgrep", help="Output root. Default: runs/semgrep.")
    ap.add_argument("--repos-dir", default="repos", help="Repos base dir. Default: repos.")
    ap.add_argument("--timeout-seconds", type=int, default=0, help="Semgrep timeout. 0 = no timeout.")

    ns = ap.parse_args()

    # Preserve prior interactive behavior: prompt if neither is provided.
    if not ns.repo_url and not ns.repo_path:
        ns.repo_url = input("Enter Git repo URL to scan: ").strip()

    if ns.repo_url and ns.repo_path:
        raise SystemExit("Provide only one of --repo-url or --repo-path.")

    if not ns.repo_url and not ns.repo_path:
        raise SystemExit("Provide --repo-url or --repo-path.")

    return ns


# ---------------------------------------------------------------------------
# Run directory layout
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RunPaths:
    run_dir: Path
    raw_results: Path
    normalized: Path
    metadata: Path


def prepare_run_paths(output_root: str, repo_name: str) -> Tuple[str, RunPaths]:
    run_id, run_dir = create_run_dir_compat(Path(output_root) / repo_name)
    return run_id, RunPaths(
        run_dir=run_dir,
        raw_results=run_dir / f"{repo_name}.json",
        normalized=run_dir / f"{repo_name}.normalized.json",
        metadata=run_dir / "metadata.json",
    )


# ---------------------------------------------------------------------------
# Semgrep execution
# ---------------------------------------------------------------------------

def semgrep_version(semgrep_bin: str) -> str:
    res = run_cmd([semgrep_bin, "--version"], print_stderr=False, print_stdout=False)
    return (res.stdout or res.stderr).strip() or "unknown"


def run_semgrep(
    *,
    semgrep_bin: str,
    repo_path: Path,
    config: str,
    output_path: Path,
    timeout_seconds: int = 0,
) -> Tuple[int, float, str]:
    cmd = [
        semgrep_bin,
        "--json",
        "--config",
        config,
        "--output",
        str(output_path),
    ]

    print(f"\n🔍 Running Semgrep on {repo_path.name} ...")
    print("Command:", " ".join(cmd))

    res = run_cmd(cmd, cwd=repo_path, timeout_seconds=timeout_seconds, print_stderr=True, print_stdout=False)
    return res.exit_code, res.elapsed_seconds, res.command_str


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def map_semgrep_severity(sev: Optional[str]) -> Optional[str]:
    """Normalize Semgrep severity to HIGH/MEDIUM/LOW (matching prior behavior)."""
    if sev is None:
        return None
    s = str(sev).strip().upper()
    if s in {"ERROR", "CRITICAL"}:
        return "HIGH"
    if s == "WARNING":
        return "MEDIUM"
    if s == "INFO":
        return "LOW"
    if s in {"HIGH", "MEDIUM", "LOW"}:
        return s
    return "MEDIUM"


# ---------------------------------------------------------------------------
# Normalize Semgrep JSON to schema v1.1
# ---------------------------------------------------------------------------

def normalize_semgrep_results(
    *,
    repo_path: Path,
    raw_results_path: Path,
    metadata: Dict[str, Any],
    normalized_path: Path,
) -> None:
    # Align header blocks with other scanners using normalize_common.
    target_repo = build_target_repo(metadata)
    scan_info = build_scan_info(metadata, raw_results_path)
    per_finding_metadata = build_per_finding_metadata(
        tool="semgrep",
        tool_version=metadata.get("scanner_version"),
        target_repo=target_repo,
        scan_info=scan_info,
    )

    if not raw_results_path.exists():
        write_json(
            normalized_path,
            {
                "schema_version": "1.1",
                "tool": "semgrep",
                "tool_version": metadata.get("scanner_version"),
                "target_repo": target_repo,
                "scan": scan_info,
                "run_metadata": metadata,
                "findings": [],
            },
        )
        return

    raw = read_json(raw_results_path)
    results = raw.get("results") or []

    cwe_to_owasp_map = load_cwe_to_owasp_map()

    findings: List[Dict[str, Any]] = []

    for res in results if isinstance(results, list) else []:
        if not isinstance(res, dict):
            continue

        rule_id = res.get("check_id")

        loc = extract_location(res, tool="semgrep")
        file_path = normalize_repo_relative_path(repo_path, loc.file_path)
        line = loc.line_number
        end_line = loc.end_line_number or line

        line_content = read_line_content(repo_path, file_path, line) if file_path and line else None

        extra = res.get("extra") or {}
        extra = extra if isinstance(extra, dict) else {}

        message = extra.get("message")
        severity_norm = map_semgrep_severity(extra.get("severity"))

        meta = extra.get("metadata") or {}
        meta = meta if isinstance(meta, dict) else {}

        semgrep_owasp_tags = _as_list(meta.get("owasp"))
        vuln_class_list = _as_list(meta.get("vulnerability_class"))
        vuln_class = str(vuln_class_list[0]) if vuln_class_list else None

        # Prefer extractor for CWE candidates (covers list/int/strings + nested shapes).
        cwe_candidates = extract_cwe_candidates(meta) or _as_list(meta.get("cwe"))

        # Feed shared resolver (same policy as Snyk/Aikido).
        tags: List[str] = []
        tags += [str(x) for x in semgrep_owasp_tags if x is not None]
        tags += [str(x) for x in vuln_class_list if x is not None]
        tags += [str(x) for x in _as_list(meta.get("category")) if x is not None]
        tags += [str(x) for x in _as_list(meta.get("technology")) if x is not None]
        tags += [str(x) for x in _as_list(meta.get("subcategory")) if x is not None]

        classification = resolve_owasp_and_cwe(
            tags=tags,
            cwe_candidates=cwe_candidates,
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

                # match Snyk/Sonar normalized fields
                "cwe_id": classification.get("cwe_id"),
                "cwe_ids": classification.get("cwe_ids") or [],
                "vuln_class": vuln_class,
                "owasp_top_10_2017": classification.get("owasp_top_10_2017"),
                "owasp_top_10_2021": classification.get("owasp_top_10_2021"),

                "vendor": {"raw_result": res},
            }
        )

    write_json(
        normalized_path,
        {
            "schema_version": "1.1",
            "tool": "semgrep",
            "tool_version": metadata.get("scanner_version"),
            "target_repo": target_repo,
            "scan": scan_info,
            "run_metadata": metadata,
            "findings": findings,
        },
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    repo = acquire_repo(repo_url=args.repo_url, repo_path=args.repo_path, repos_dir=args.repos_dir)

    semgrep_bin = which_or_raise("semgrep", fallbacks=SEMGREP_FALLBACKS)

    run_id, paths = prepare_run_paths(args.output_root, repo.repo_name)

    exit_code, elapsed, command_str = run_semgrep(
        semgrep_bin=semgrep_bin,
        repo_path=repo.repo_path,
        config=args.config,
        output_path=paths.raw_results,
        timeout_seconds=args.timeout_seconds,
    )

    meta = build_run_metadata(
        scanner="semgrep",
        scanner_version=semgrep_version(semgrep_bin),
        repo=repo,
        run_id=run_id,
        command_str=command_str,
        scan_time_seconds=elapsed,
        exit_code=exit_code,
        extra={"semgrep_config": args.config},
    )
    write_json(paths.metadata, meta)

    print("📄 Raw JSON saved to:", paths.raw_results)
    print("📄 Metadata saved to:", paths.metadata)

    normalize_semgrep_results(
        repo_path=repo.repo_path,
        raw_results_path=paths.raw_results,
        metadata=meta,
        normalized_path=paths.normalized,
    )

    print("📄 Normalized JSON saved to:", paths.normalized)


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as e:
        # Make missing semgrep a clean error (not a giant traceback)
        print(f"❌ {e}", file=sys.stderr)
        raise SystemExit(127)
