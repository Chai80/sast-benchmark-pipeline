#!/usr/bin/env python3
"""
Simple CLI wrapper for the SAST pipeline (benchmark-free).

Modes:
  1) scan      - run one scanner against one repo
  2) benchmark - run multiple scanners against one repo (simple loop)

Usage:
  python sast_cli.py
  python sast_cli.py --mode scan --scanner snyk --repo-key juice_shop
  python sast_cli.py --mode scan --scanner semgrep --repo-url https://github.com/juice-shop/juice-shop.git
  python sast_cli.py --mode benchmark --repo-key juice_shop --scanners semgrep,snyk
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Centralized command builder (prevents per-CLI drift)
from pipeline.core import (
    ROOT_DIR as PIPELINE_ROOT_DIR,
    SUPPORTED_SCANNERS,
    build_scan_command,
    derive_sonar_project_key,
    repo_id_from_repo_url,
    sanitize_sonar_key_fragment,
)

ROOT_DIR = PIPELINE_ROOT_DIR  # repo root
ENV_PATH = ROOT_DIR / ".env"

# Replace/add your preset repos here (this replaces benchmarks/targets.py)
REPOS: Dict[str, Dict[str, str]] = {
    "juice_shop": {"label": "Juice Shop", "repo_url": "https://github.com/juice-shop/juice-shop.git"},
    "webgoat": {"label": "WebGoat", "repo_url": "https://github.com/WebGoat/WebGoat.git"},
    "dvwa": {"label": "DVWA", "repo_url": "https://github.com/digininja/DVWA.git"},
    "owasp_benchmark": {"label": "OWASP BenchmarkJava", "repo_url": "https://github.com/OWASP/BenchmarkJava.git"},
}

SCANNER_LABELS: Dict[str, str] = {
    "semgrep": "Semgrep",
    "sonar": "SonarCloud",
    "snyk": "Snyk Code",
    "aikido": "Aikido",
}


# -------------------------------------------------------------------
# .env loader (no dependency)
# -------------------------------------------------------------------

def load_dotenv_if_present(dotenv_path: Path) -> None:
    """
    Minimal .env loader. Loads KEY=VALUE into os.environ if not already set.
    - Ignores comments/blank lines
    - Supports quoted values
    - Supports inline comments of the form: VALUE   # comment
    """
    if not dotenv_path.exists():
        return

    for raw in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, val = line.split("=", 1)
        key = key.strip()
        raw_val = val.strip()

        # Quoted value
        if (raw_val.startswith('"') and raw_val.endswith('"')) or (raw_val.startswith("'") and raw_val.endswith("'")):
            parsed_val = raw_val[1:-1]
        else:
            # Strip inline comments only when preceded by whitespace: "VALUE   # comment"
            parsed_val = re.split(r"\s+#", raw_val, maxsplit=1)[0].strip()
            parsed_val = parsed_val.strip('"').strip("'")

        parsed_val = parsed_val.replace("\r", "")
        if key and key not in os.environ:
            os.environ[key] = parsed_val


def require_env(var: str) -> None:
    if not os.getenv(var):
        raise SystemExit(f"Missing {var}. Put it in {ENV_PATH} (or export it in your shell).")


# -------------------------------------------------------------------
# Helper: select from a menu
# -------------------------------------------------------------------

def choose_from_menu(title: str, options: Dict[str, object]) -> str:
    """
    Show a 1..N menu of keys in 'options' and return the chosen key.
    Input rules:
      - Only accepts numbers 1..N
      - 'Z' exits
    """
    keys = list(options.keys())
    print("\n" + title)
    for idx, key in enumerate(keys, start=1):
        val = options[key]
        # pretty label
        if isinstance(val, dict) and "label" in val:
            label = str(val["label"])
        else:
            label = str(val)
        print(f"[{idx}] {label} ({key})")

    while True:
        choice = input(f"Enter number (1-{len(keys)}) or Z to exit: ").strip()
        if not choice:
            print("Please enter a number or Z to exit.")
            continue
        if choice.upper() == "Z":
            print("Exiting (Z selected).")
            raise SystemExit(0)
        if choice.isdigit():
            n = int(choice)
            if 1 <= n <= len(keys):
                return keys[n - 1]
        print(f"Invalid choice. Please enter 1-{len(keys)} or Z.")


# -------------------------------------------------------------------
# CLI entrypoint
# -------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Top-level CLI for SAST pipeline (no benchmarks package).")

    parser.add_argument("--mode", choices=["scan", "benchmark"], help="scan = one tool, benchmark = multiple tools")
    parser.add_argument(
        "--scanner",
        choices=sorted(SUPPORTED_SCANNERS),
        help="(scan mode) Which scanner to run",
    )
    parser.add_argument(
        "--scanners",
        help="(benchmark mode) Comma-separated scanners (default: semgrep,snyk,sonar,aikido)",
    )

    # Repo selection (either preset key, or custom URL/path)
    parser.add_argument("--repo-key", choices=sorted(REPOS.keys()), help="Preset repo key (recommended)")
    parser.add_argument("--repo-url", help="Custom git repo URL")
    parser.add_argument("--repo-path", help="Local repo path (skip clone)")

    # Sonar-specific
    parser.add_argument(
        "--sonar-project-key",
        help="(sonar only) Override SonarCloud project key. If omitted, we derive ORG_<repo_id>.",
    )

    parser.add_argument("--dry-run", action="store_true", help="Print commands but do not execute")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress scanner stdout/stderr (not recommended for debugging)",
    )
    return parser.parse_args()


def resolve_repo(args: argparse.Namespace) -> Tuple[Optional[str], Optional[str], str, str]:
    """
    Returns (repo_url, repo_path, label, repo_id)

    repo_id is a stable identifier used for Sonar project key derivation.
    - For presets: it's the preset key (e.g., juice_shop)
    - For custom URLs: derived from the URL repo name (sanitized)
    - For local paths: derived from folder name (sanitized)
    """
    if args.repo_key:
        entry = REPOS[args.repo_key]
        return entry.get("repo_url"), None, entry.get("label", args.repo_key), args.repo_key

    if args.repo_path:
        p = Path(args.repo_path).resolve()
        rid = sanitize_sonar_key_fragment(p.name)
        return args.repo_url, str(p), p.name, rid

    if args.repo_url:
        rid = repo_id_from_repo_url(args.repo_url)
        return args.repo_url, None, args.repo_url, rid

    # interactive fallback
    choice = choose_from_menu(
        "Choose a repo source:",
        {
            "preset": "Pick from preset repos",
            "custom_url": "Enter a custom repo URL",
            "local_path": "Use a local repo path",
        },
    )

    if choice == "preset":
        key = choose_from_menu("Choose a preset repo:", {k: v["label"] for k, v in REPOS.items()})
        entry = REPOS[key]
        return entry.get("repo_url"), None, entry.get("label", key), key

    if choice == "custom_url":
        while True:
            url = input("Enter full repo URL (https://... .git or git@...): ").strip()
            if url.startswith(("https://", "http://", "git@")):
                rid = repo_id_from_repo_url(url)
                return url, None, url, rid
            print("That doesn't look like a git URL. Try again.")

    # local_path
    while True:
        path = input("Enter local repo path: ").strip()
        if path:
            p = Path(path).resolve()
            rid = sanitize_sonar_key_fragment(p.name)
            return None, str(p), p.name, rid
        print("Empty path. Try again.")


def run_one(cmd: List[str], dry_run: bool, quiet: bool = False) -> int:
    print("  Command :", " ".join(cmd))
    if dry_run:
        print("  (dry-run: not executing)")
        return 0

    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")

    if quiet:
        result = subprocess.run(
            cmd,
            env=env,
            cwd=str(ROOT_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        result = subprocess.run(
            cmd,
            env=env,
            cwd=str(ROOT_DIR),
        )
    return result.returncode


def sonar_extra_args(args: argparse.Namespace, repo_id: str) -> Dict[str, str]:
    """Compute sonar-specific args (currently just --project-key)."""
    require_env("SONAR_ORG")
    require_env("SONAR_TOKEN")

    if args.sonar_project_key:
        project_key = args.sonar_project_key
    else:
        project_key = derive_sonar_project_key(os.environ["SONAR_ORG"], repo_id)

    return {"project-key": project_key}


def main() -> None:
    # Always load .env from repo root so terminal runs behave like PyCharm runs
    load_dotenv_if_present(ENV_PATH)

    args = parse_args()

    # mode selection
    mode = args.mode
    if mode is None:
        # If user passed scan flags, assume scan; else show menu
        if args.scanner or args.repo_key or args.repo_url or args.repo_path:
            mode = "scan"
        else:
            mode = choose_from_menu(
                "Choose an action:",
                {"scan": "Scan a repo with a single tool", "benchmark": "Run multiple scanners on a repo"},
            )

    repo_url, repo_path, label, repo_id = resolve_repo(args)

    # --------------------- SCAN MODE ---------------------
    if mode == "scan":
        scanner = args.scanner
        if scanner is None:
            # interactive menu
            scanner = choose_from_menu(
                "Choose a scanner:",
                {k: SCANNER_LABELS.get(k, k) for k in sorted(SUPPORTED_SCANNERS)},
            )

        extra_args: Dict[str, object] = {}
        if scanner == "sonar":
            extra_args = sonar_extra_args(args, repo_id)
            print(f"  Sonar project key : {extra_args.get('project-key')}")

        cmd = build_scan_command(
            scanner,
            repo_url=repo_url,
            repo_path=repo_path,
            extra_args=extra_args,
            python_executable=sys.executable or "python",
        )

        print("\n🚀 Running scan")
        print(f"  Scanner : {scanner}")
        print(f"  Target  : {label}")

        code = run_one(cmd, args.dry_run, args.quiet)

        if code == 0:
            print("\n✅ Scan completed.")
        else:
            print(f"\n⚠️ Scan finished with exit code {code}")
        raise SystemExit(code)

    # ------------------- BENCHMARK MODE ------------------
    scanners_arg = args.scanners or "semgrep,snyk,sonar,aikido"
    scanners = [s.strip() for s in scanners_arg.split(",") if s.strip()]
    scanners = [s for s in scanners if s in SUPPORTED_SCANNERS]

    if not scanners:
        raise SystemExit("No valid scanners specified for benchmark mode.")

    print("\n🚀 Running benchmark (multi-scanner loop)")
    print(f"  Target   : {label}")
    print(f"  Scanners : {', '.join(scanners)}")

    overall = 0
    for scanner in scanners:
        print("\n----------------------------------------")
        print(f"▶ {scanner}")

        extra_args: Dict[str, object] = {}
        if scanner == "sonar":
            extra_args = sonar_extra_args(args, repo_id)
            print(f"  Sonar project key : {extra_args.get('project-key')}")

        cmd = build_scan_command(
            scanner,
            repo_url=repo_url,
            repo_path=repo_path,
            extra_args=extra_args,
            python_executable=sys.executable or "python",
        )

        code = run_one(cmd, args.dry_run, args.quiet)
        if code != 0:
            overall = code

    if overall == 0:
        print("\n✅ Benchmark completed (all scanners exited 0).")
    else:
        print(f"\n⚠️ Benchmark completed with non-zero exit code: {overall}")
    raise SystemExit(overall)


if __name__ == "__main__":
    main()
