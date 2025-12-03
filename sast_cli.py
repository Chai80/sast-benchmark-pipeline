#!/usr/bin/env python3
"""
Simple CLI wrapper for the SAST benchmark pipeline.

Modes:
    1. Scan a repo with a single tool
    2. Run benchmarks (e.g. runtime benchmark across tools)

Usage (interactive menus):
    python sast_cli.py

Usage (non-interactive examples):
    # Single scan
    python sast_cli.py --mode scan --scanner snyk --target juice_shop

    # Runtime benchmark (all tools)
    python sast_cli.py --mode benchmark --target juice_shop

    # Runtime benchmark (subset of tools)
    python sast_cli.py --mode benchmark --target juice_shop --scanners semgrep,snyk
"""

import argparse
import subprocess
import sys
from pathlib import Path

# Use the same Python interpreter / venv as this script
PYTHON = sys.executable or "python"

# Central benchmark config (repos + suites)
from benchmarks.targets import BENCHMARKS, BENCHMARK_SUITES


# -------------------------------------------------------------------
#  Helper: select from a menu if user didn't pass flags
# -------------------------------------------------------------------


def choose_from_menu(title: str, options: dict) -> str:
    """
    Show a 1..N menu of keys in 'options' and return the chosen key.

    Input rules:
      - Only accepts numbers 1..N
      - 'Z' or 'z' exits the CLI immediately
    """
    keys = list(options.keys())
    print(title)
    for idx, key in enumerate(keys, start=1):
        label = (
            options[key].get("label", key)
            if isinstance(options[key], dict)
            else options[key]
        )
        print(f"[{idx}] {label} ({key})")

    while True:
        choice = input(f"Enter number (1-{len(keys)}) or Z to exit: ").strip()
        if not choice:
            print("Please enter a number or Z to exit.")
            continue

        # Allow Z/z to exit the whole CLI
        if choice.upper() == "Z":
            print("Exiting (Z selected).")
            sys.exit(0)

        # Only accept valid numeric options
        if choice.isdigit():
            n = int(choice)
            if 1 <= n <= len(keys):
                return keys[n - 1]

        print(
            f"Invalid choice. Please enter a number between 1 and {len(keys)} "
            "or Z to exit."
        )


# -------------------------------------------------------------------
#  Build commands for each scanner (scan mode)
# -------------------------------------------------------------------


def build_command(scanner: str, target_key: str) -> list[str]:
    """
    Given a scanner name and a benchmark key, return the command list
    we should run, e.g.:
        ['python', 'tools/scan_snyk.py', '--repo-url', 'https://...']
    """
    if target_key not in BENCHMARKS:
        raise ValueError(f"Unknown target '{target_key}'")

    target = BENCHMARKS[target_key]
    project_root = Path(__file__).resolve().parent
    tools_dir = project_root / "tools"

    if scanner == "semgrep":
        return [
            PYTHON,
            str(tools_dir / "scan_semgrep.py"),
            "--repo-url",
            target["repo_url"],
        ]

    if scanner == "snyk":
        return [
            PYTHON,
            str(tools_dir / "scan_snyk.py"),
            "--repo-url",
            target["repo_url"],
        ]

    if scanner == "sonar":
        cmd = [
            PYTHON,
            str(tools_dir / "scan_sonar.py"),
            "--repo-url",
            target["repo_url"],
        ]
        # If we have a known project key, pass it
        if target.get("sonar_project_key"):
            cmd.extend(["--project-key", target["sonar_project_key"]])
        return cmd

    if scanner == "aikido":
        # Aikido uses --git-ref instead of --repo-url
        return [
            PYTHON,
            str(tools_dir / "scan_aikido.py"),
            "--git-ref",
            target["aikido_ref"],
        ]

    raise ValueError(f"Unknown scanner '{scanner}'")


# -------------------------------------------------------------------
#  CLI entrypoint
# -------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Top-level CLI for SAST benchmark pipeline."
    )

    # High-level mode: scan vs benchmark
    parser.add_argument(
        "--mode",
        choices=["scan", "benchmark"],
        help="What to run: a single scan or a benchmark suite.",
    )

    # Scan-mode arguments
    parser.add_argument(
        "--scanner",
        choices=["semgrep", "sonar", "snyk", "aikido"],
        help="(scan mode) Which scanner to run.",
    )
    parser.add_argument(
        "--target",
        choices=list(BENCHMARKS.keys()),
        help="Which benchmark repo to scan / benchmark.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="(scan mode) Print the command that would be run, but do not execute it.",
    )

    # Benchmark-mode arguments
    parser.add_argument(
        "--scanners",
        help=(
            "(benchmark mode) Comma-separated list of scanners to benchmark "
            "(default inside runtime.py is: semgrep,snyk,sonar,aikido)"
        ),
    )
    parser.add_argument(
        "--no-save-benchmark",
        action="store_true",
        help="(benchmark mode) Do not write benchmark summary JSON to runs/benchmarks/.",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Decide mode:
    #  - If user passed --mode, use it.
    #  - Else, if they passed --scanner/--target, assume 'scan'.
    #  - Else, show a top-level menu: Scan vs Benchmark.
    mode = args.mode
    if mode is None:
        if args.scanner or args.target or args.dry_run:
            mode = "scan"
        else:
            mode = choose_from_menu(
                "Choose an action:",
                {
                    "scan": "Scan a repo with a single tool",
                    "benchmark": "Run benchmarks",
                },
            )

    project_root = Path(__file__).resolve().parent
    benchmarks_dir = project_root / "benchmarks"

    # --------------------- SCAN MODE ---------------------
    if mode == "scan":
        scanner = args.scanner
        target = args.target

        # If flags not provided, fall back to interactive menus
        if scanner is None:
            scanner = choose_from_menu(
                "Choose a scanner:",
                {
                    "semgrep": "Semgrep",
                    "sonar": "SonarCloud",
                    "snyk": "Snyk Code",
                    "aikido": "Aikido",
                },
            )

        if target is None:
            target = choose_from_menu("Choose a benchmark target:", BENCHMARKS)

        cmd = build_command(scanner, target)

        print("\n🚀 Running scan")
        print(f"  Scanner : {scanner}")
        print(f"  Target  : {BENCHMARKS[target]['label']} ({target})")
        print("  Command :", " ".join(cmd))

        if args.dry_run:
            print("\n(dry-run: not executing)")
            return

        # Actually run the underlying scan script
        result = subprocess.run(cmd)
        if result.returncode == 0:
            print("\n✅ Scan completed.")
        else:
            print(f"\n⚠️ Scan finished with exit code {result.returncode}")
        return

    # ------------------- BENCHMARK MODE ------------------
    if mode == "benchmark":
        # 1) Choose which repo/target we are benchmarking
        target = args.target
        if target is None:
            target = choose_from_menu("Choose a benchmark target:", BENCHMARKS)

        # 2) Choose which benchmark suite to run (in future, there can be more)
        suite = choose_from_menu("Choose a benchmark to run:", BENCHMARK_SUITES)

        # For now we only have 'runtime'
        if suite == "runtime":
            scanners_arg = args.scanners or "semgrep,snyk,sonar,aikido"

            benchmark_cmd = [
                PYTHON,
                str(benchmarks_dir / "runtime.py"),
                "--target",
                target,
                "--scanners",
                scanners_arg,
            ]
            if args.no_save_benchmark:
                benchmark_cmd.append("--no-save")

            print("\n🚀 Running runtime benchmark")
            print(f"  Target   : {BENCHMARKS[target]['label']} ({target})")
            print(f"  Scanners : {scanners_arg}")
            print("  Command  :", " ".join(benchmark_cmd))

            result = subprocess.run(benchmark_cmd)
            if result.returncode == 0:
                print("\n✅ Benchmark completed.")
            else:
                print(f"\n⚠️ Benchmark finished with exit code {result.returncode}")
            return

        # Defensive: unknown suite (shouldn't happen with the menu)
        print(f"⚠️ Unknown benchmark suite '{suite}'. Nothing to do.")
        return


if __name__ == "__main__":
    main()
