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
    python sast_cli.py --mode benchmark --target juice_shop --suite runtime

    # Runtime benchmark (subset of tools)
    python sast_cli.py --mode benchmark --target juice_shop --suite runtime --scanners semgrep,snyk
"""

import argparse
import subprocess
import sys
from pathlib import Path

# Use the same Python interpreter / venv as this script
PYTHON = sys.executable or "python"

# Central benchmark config (repos + suites)
from benchmarks.targets import BENCHMARKS, BENCHMARK_SUITES

# Core command builder (neutral layer, not the CLI)
from pipeline.core import build_command


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
        val = options[key]
        label = val.get("label", key) if isinstance(val, dict) else str(val)
        print(f"[{idx}] {label} ({key})")

    while True:
        choice = input(f"Enter number (1-{len(keys)}) or Z to exit: ").strip()
        if not choice:
            print("Please enter a number or Z to exit.")
            continue

        if choice.upper() == "Z":
            print("Exiting (Z selected).")
            sys.exit(0)

        if choice.isdigit():
            n = int(choice)
            if 1 <= n <= len(keys):
                return keys[n - 1]

        print(
            f"Invalid choice. Please enter a number between 1 and {len(keys)} "
            "or Z to exit."
        )


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
        "--suite",
        choices=list(BENCHMARK_SUITES.keys()),
        help="(benchmark mode) Which benchmark suite to run (e.g. runtime).",
    )
    parser.add_argument(
        "--scanners",
        help=(
            "(benchmark mode) Comma-separated list of scanners to benchmark "
            "(default: semgrep,snyk,sonar,aikido)"
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

        # Command comes from pipeline core (not from CLI)
        cmd = build_command(scanner, target)

        label = BENCHMARKS[target].get("label", target)

        print("\n🚀 Running scan")
        print(f"  Scanner : {scanner}")
        print(f"  Target  : {label} ({target})")
        print("  Command :", " ".join(cmd))

        if args.dry_run:
            print("\n(dry-run: not executing)")
            return

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

        # 2) Choose which benchmark suite (menu unless passed as flag)
        suite = args.suite
        if suite is None:
            suite = choose_from_menu("Choose a benchmark to run:", BENCHMARK_SUITES)

        label = BENCHMARKS[target].get("label", target)

        # For now we only have 'runtime'
        if suite == "runtime":
            scanners_arg = args.scanners or "semgrep,snyk,sonar,aikido"

            # Run as a module so imports work cleanly (no sys.path hacks)
            benchmark_cmd = [
                PYTHON,
                "-m",
                "benchmarks.runtime",
                "--target",
                target,
                "--scanners",
                scanners_arg,
            ]
            if args.no_save_benchmark:
                benchmark_cmd.append("--no-save")

            print("\n🚀 Running runtime benchmark")
            print(f"  Target   : {label} ({target})")
            print(f"  Scanners : {scanners_arg}")
            print("  Command  :", " ".join(benchmark_cmd))

            result = subprocess.run(benchmark_cmd)
            if result.returncode == 0:
                print("\n✅ Benchmark completed.")
            else:
                print(f"\n⚠️ Benchmark finished with exit code {result.returncode}")
            return

        print(f"⚠️ Unknown benchmark suite '{suite}'. Nothing to do.")
        return


if __name__ == "__main__":
    main()
