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
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Use the same Python interpreter / venv as this script
PYTHON = sys.executable or "python"

ROOT_DIR = Path(__file__).resolve().parent
TOOLS_DIR = ROOT_DIR / "tools"

SUPPORTED_SCANNERS: Dict[str, str] = {
    "semgrep": "scan_semgrep.py",
    "sonar": "scan_sonar.py",
    "snyk": "scan_snyk.py",
    "aikido": "scan_aikido.py",
}

# Replace/add your preset repos here (this replaces benchmarks/targets.py)
REPOS: Dict[str, Dict[str, str]] = {
    "juice_shop": {"label": "Juice Shop", "repo_url": "https://github.com/juice-shop/juice-shop.git"},
    "webgoat": {"label": "WebGoat", "repo_url": "https://github.com/WebGoat/WebGoat.git"},
    "dvwa": {"label": "DVWA", "repo_url": "https://github.com/digininja/DVWA.git"},
    "owasp_benchmark": {"label": "OWASP BenchmarkJava", "repo_url": "https://github.com/OWASP/BenchmarkJava.git"},
}


# -------------------------------------------------------------------
# .env loader (no dependency)
# -------------------------------------------------------------------

def load_dotenv_if_present(dotenv_path: Path) -> None:
    """
    Minimal .env loader. Loads KEY=VALUE into os.environ if not already set.
    - Ignores comments/blank lines
    - Supports quoted values
    """
    if not dotenv_path.exists():
        return
    for raw in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


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
    parser.add_argument("--scanner", choices=sorted(SUPPORTED_SCANNERS.keys()), help="(scan mode) Which scanner to run")
    parser.add_argument("--scanners", help="(benchmark mode) Comma-separated scanners (default: semgrep,snyk,sonar,aikido)")

    # Repo selection (either preset key, or custom URL/path)
    parser.add_argument("--repo-key", choices=sorted(REPOS.keys()), help="Preset repo key (recommended)")
    parser.add_argument("--repo-url", help="Custom git repo URL")
    parser.add_argument("--repo-path", help="Local repo path (skip clone)")

    parser.add_argument("--dry-run", action="store_true", help="Print commands but do not execute")
    return parser.parse_args()


def resolve_repo(args: argparse.Namespace) -> Tuple[Optional[str], Optional[str], str]:
    """
    Returns (repo_url, repo_path, label)
    """
    if args.repo_key:
        entry = REPOS[args.repo_key]
        return entry.get("repo_url"), None, entry.get("label", args.repo_key)

    if args.repo_path:
        p = Path(args.repo_path).resolve()
        return args.repo_url, str(p), p.name

    if args.repo_url:
        return args.repo_url, None, args.repo_url

    # interactive fallback
    # choose preset or custom
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
        return entry.get("repo_url"), None, entry.get("label", key)

    if choice == "custom_url":
        while True:
            url = input("Enter full repo URL (https://... .git or git@...): ").strip()
            if url.startswith(("https://", "http://", "git@")):
                return url, None, url
            print("That doesn't look like a git URL. Try again.")

    # local_path
    while True:
        path = input("Enter local repo path: ").strip()
        if path:
            p = Path(path).resolve()
            return None, str(p), p.name
        print("Empty path. Try again.")


def build_scan_command(scanner: str, repo_url: Optional[str], repo_path: Optional[str]) -> List[str]:
    script = SUPPORTED_SCANNERS[scanner]
    script_path = TOOLS_DIR / script
    if not script_path.exists():
        raise SystemExit(f"Scanner script not found: {script_path}")

    cmd = [PYTHON, str(script_path)]

    # ---- Aikido special case ----
    if scanner == "aikido":
        # Aikido does NOT accept repo-url; it wants a git ref / slug
        if not repo_url:
            raise SystemExit("Aikido requires a repo URL to derive --git-ref.")
        git_ref = repo_url.rstrip("/").replace(".git", "")
        cmd += ["--git-ref", git_ref]
        return cmd

    # ---- All other scanners ----
    if repo_path:
        cmd += ["--repo-path", repo_path]
        if repo_url:
            cmd += ["--repo-url", repo_url]
        return cmd

    if not repo_url:
        raise SystemExit("Missing repo_url/repo_path.")
    cmd += ["--repo-url", repo_url]
    return cmd

def run_one(cmd: List[str], dry_run: bool) -> int:
    print("  Command :", " ".join(cmd))
    if dry_run:
        print("  (dry-run: not executing)")
        return 0

    result = subprocess.run(
        cmd,
        env=os.environ.copy(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode



def main() -> None:
    # ✅ Always load .env from repo root so terminal runs behave like PyCharm runs
    load_dotenv_if_present(ROOT_DIR / ".env")

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

    repo_url, repo_path, label = resolve_repo(args)

    # --------------------- SCAN MODE ---------------------
    if mode == "scan":
        scanner = args.scanner
        if scanner is None:
            scanner = choose_from_menu(
                "Choose a scanner:",
                {"semgrep": "Semgrep", "sonar": "SonarCloud", "snyk": "Snyk Code", "aikido": "Aikido"},
            )

        cmd = build_scan_command(scanner, repo_url, repo_path)

        print("\n🚀 Running scan")
        print(f"  Scanner : {scanner}")
        print(f"  Target  : {label}")
        code = run_one(cmd, args.dry_run)

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
        cmd = build_scan_command(scanner, repo_url, repo_path)
        code = run_one(cmd, args.dry_run)
        if code != 0:
            overall = code

    if overall == 0:
        print("\n✅ Benchmark completed (all scanners exited 0).")
    else:
        print(f"\n⚠️ Benchmark completed with non-zero exit code: {overall}")
    raise SystemExit(overall)


if __name__ == "__main__":
    main()
