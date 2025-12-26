#!/usr/bin/env python3
"""
tools/scan_semgrep.py

Semgrep scanner wrapper for sast-benchmark-pipeline.

Outputs:
  runs/semgrep/<repo_name>/<run_id>/
    - <repo_name>.json
    - metadata.json
    - <repo_name>.normalized.json

Goals
-----
- Keep this file a thin orchestrator (like scan_snyk.py)
- Reuse tools/core.py for shared plumbing (repo acquisition, run dirs, JSON IO, commands)
- Reuse tools/classification_resolver.py for consistent CWE/OWASP mapping
- Emit a scan block consistent with Sonar/Aikido using tools/normalize_common.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---- Robust imports (script execution vs module import) ----
try:
    from core import (  # type: ignore
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
except ImportError:
    from tools.core import (  # type: ignore
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

try:
    from classification_resolver import resolve_owasp_and_cwe
except ImportError:
    from tools.classification_resolver import resolve_owasp_and_cwe  # type: ignore

try:
    # When running as a script from tools/, this works.
    from normalize_common import (  # type: ignore
        build_per_finding_metadata,
        build_scan_info,
        build_target_repo,
    )
except ImportError:
    # When imported as tools.scan_semgrep, this is the correct path.
    from tools.normalize_common import (  # type: ignore
        build_per_finding_metadata,
        build_scan_info,
        build_target_repo,
    )


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

    # Preserve the prior interactive behavior: prompt if neither is provided.
    if not ns.repo_url and not ns.repo_path:
        ns.repo_url = input("Enter Git repo URL to scan: ").strip()

    if ns.repo_url and ns.repo_path:
        raise SystemExit("Provide only one of --repo-url or --repo-path.")

    if not ns.repo_url and not ns.repo_path:
        raise SystemExit("Provide --repo-url or --repo-path.")

    return ns


# -------------------------
# Semgrep execution
# -------------------------

def semgrep_version(semgrep_bin: str) -> str:
    res = run_cmd([semgrep_bin, "--version"], print_stderr=False, print_stdout=False)
    return (res.stdout or res.stderr).strip() or "unknown"


def run_semgrep(
    repo_path: Path,
    config: str,
    output_path: Path,
    timeout_seconds: int = 0,
) -> Tuple[int, float, str]:
    semgrep_bin = which_or_raise("semgrep", fallbacks=["/opt/homebrew/bin/semgrep", "/usr/local/bin/semgrep"])

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


# -------------------------
# Normalize Semgrep JSON to schema v1.1
# -------------------------

def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def map_semgrep_severity(sev: Optional[str]) -> Optional[str]:
    """Normalize Semgrep severity to HIGH/MEDIUM/LOW."""
    if not sev:
        return None
    s = str(sev).strip().upper()
    if s in {"ERROR", "CRITICAL"}:
        return "HIGH"
    if s in {"WARNING"}:
        return "MEDIUM"
    if s in {"INFO"}:
        return "LOW"
    if s in {"HIGH", "MEDIUM", "LOW"}:
        return s
    return "MEDIUM"


def normalize_semgrep_results(
    repo_path: Path,
    raw_results_path: Path,
    metadata: Dict[str, Any],
    normalized_path: Path,
) -> None:
    # Align header blocks with other scanners (Sonar/Aikido) using normalize_common.
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

        file_path = normalize_repo_relative_path(repo_path, res.get("path"))
        start = res.get("start") or {}
        end = res.get("end") or {}
        line = start.get("line")
        end_line = end.get("line", line)

        line_content = read_line_content(repo_path, file_path, int(line)) if file_path and line else None

        extra = res.get("extra") or {}
        message = extra.get("message")
        severity_norm = map_semgrep_severity(extra.get("severity"))

        meta = extra.get("metadata") or {}
        semgrep_owasp_tags = _as_list(meta.get("owasp"))
        semgrep_cwe_candidates = _as_list(meta.get("cwe"))
        vuln_class_list = _as_list(meta.get("vulnerability_class"))
        vuln_class = str(vuln_class_list[0]) if vuln_class_list else None

        # Feed your shared resolver (same policy as Snyk)
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


# -------------------------
# Main
# -------------------------

def main() -> None:
    args = parse_args()

    repo = acquire_repo(repo_url=args.repo_url, repo_path=args.repo_path, repos_dir=args.repos_dir)

    run_id, run_dir = create_run_dir_compat(Path(args.output_root) / repo.repo_name)

    results_path = run_dir / f"{repo.repo_name}.json"
    normalized_path = run_dir / f"{repo.repo_name}.normalized.json"
    metadata_path = run_dir / "metadata.json"

    exit_code, elapsed, command_str = run_semgrep(
        repo_path=repo.repo_path,
        config=args.config,
        output_path=results_path,
        timeout_seconds=args.timeout_seconds,
    )

    semgrep_bin = which_or_raise("semgrep", fallbacks=["/opt/homebrew/bin/semgrep", "/usr/local/bin/semgrep"])
    meta = build_run_metadata(
        scanner="semgrep",
        scanner_version=semgrep_version(semgrep_bin),
        repo=repo,
        run_id=run_id,
        command_str=command_str,
        scan_time_seconds=elapsed,
        exit_code=exit_code,
    )

    write_json(metadata_path, meta)
    print("📄 Raw JSON saved to:", results_path)
    print("📄 Metadata saved to:", metadata_path)

    normalize_semgrep_results(
        repo_path=repo.repo_path,
        raw_results_path=results_path,
        metadata=meta,
        normalized_path=normalized_path,
    )

    print("📄 Normalized JSON saved to:", normalized_path)


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as e:
        # Make missing semgrep a clean error (not a giant traceback)
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(127)
