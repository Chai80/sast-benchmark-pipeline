#!/usr/bin/env python3
"""
Simple CLI wrapper for the SAST benchmark pipeline.

Usage (interactive menus):
    python sast_cli.py

Usage (non-interactive):
    python sast_cli.py --scanner snyk --target juice_shop
"""

import argparse
import subprocess
import sys
from pathlib import Path

# Use the same Python interpreter / venv as this script
PYTHON = sys.executable or "python"

# -------------------------------------------------------------------
#  Benchmark repos we care about
#  (these match the table in your README)
# -------------------------------------------------------------------

BENCHMARKS = {
    "juice_shop": {
        "label": "Juice Shop",
        "repo_url": "https://github.com/juice-shop/juice-shop.git",
        "aikido_ref": "Chai80/juice-shop",
        "sonar_project_key": "chai80_juice_shop",
    },
    "dvpwa": {
        "label": "DVPWA",
        "repo_url": "https://github.com/vulnerable-apps/dvpwa.git",
        "aikido_ref": "Chai80/dvpwa",
        "sonar_project_key": "chai80_dvpwa",
    },
    "owasp_benchmark": {
        "label": "OWASP Benchmark (Java)",
        "repo_url": "https://github.com/OWASP-Benchmark/BenchmarkJava.git",
        "aikido_ref": "Chai80/owasp_benchmark",
        "sonar_project_key": "chai80_owasp_benchmark",
    },
    "spring_realworld": {
        "label": "Spring Boot RealWorld",
        "repo_url": "https://github.com/gothinkster/spring-boot-realworld-example-app.git",
        "aikido_ref": "Chai80/spring_realworld",
        "sonar_project_key": "chai80_spring_realworld",
    },
    "vuln_node_express": {
        "label": "vuln_node_express",
        "repo_url": "https://github.com/vulnerable-apps/vuln_node_express.git",
        "aikido_ref": "Chai80/vuln_node_express",
        "sonar_project_key": "chai80_vuln_node_express",
    },
}

# -------------------------------------------------------------------
#  Helper: select from a menu if user didn't pass flags
# -------------------------------------------------------------------


def choose_from_menu(title: str, options: dict) -> str:
    """
    Show a 1..N menu of keys in 'options' and return the chosen key.
    """
    keys = list(options.keys())
    print(title)
    for idx, key in enumerate(keys, start=1):
        label = options[key].get("label", key) if isinstance(options[key], dict) else options[key]
        print(f"[{idx}] {label} ({key})")

    while True:
        choice = input(f"Enter number (1-{len(keys)}): ").strip()
        try:
            n = int(choice)
            if 1 <= n <= len(keys):
                return keys[n - 1]
        except ValueError:
            pass
        print("Invalid choice, please try again.")


# -------------------------------------------------------------------
#  Build commands for each scanner
# -------------------------------------------------------------------


def build_command(scanner: str, target_key: str) -> list[str]:
    """
    Given a scanner name and a benchmark key, return the command list
    we should run, e.g.:
        ["python", "tools/scan_snyk.py", "--repo-url", "https://..."]
    """
    if target_key not in BENCHMARKS:
        raise ValueError(f"Unknown target '{target_key}'")

    target = BENCHMARKS[target_key]
    tools_dir = Path(__file__).resolve().parent / "tools"

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
    parser.add_argument(
        "--scanner",
        choices=["semgrep", "sonar", "snyk", "aikido"],
        help="Which scanner to run.",
    )
    parser.add_argument(
        "--target",
        choices=list(BENCHMARKS.keys()),
        help="Which benchmark repo to scan.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the command that would be run, but do not execute it.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

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


if __name__ == "__main__":
    main()
