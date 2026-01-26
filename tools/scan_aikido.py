#!/usr/bin/env python3
"""tools/scan_aikido.py

Stable Aikido entrypoint used by pipeline/core.py.

Thin shim:
  - parse CLI args
  - delegate to tools.aikido.cli_entry(...)

Implementation lives in tools/aikido/ (Option B).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.aikido import cli_entry


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run Aikido scan and export issues.\n\n"
            "Modes:\n"
            "  - cloud: use Aikido Public API (connected repos, single scanned branch).\n"
            "  - local: run Aikido Local Scanner (branch-accurate; recommended for suites)."
        )
    )

    parser.add_argument(
        "--mode",
        default="cloud",
        choices=["cloud", "local"],
        help="Backend mode: 'cloud' (API export) or 'local' (local scanner).",
    )

    # Cloud mode selector.
    parser.add_argument(
        "--git-ref",
        required=False,
        help="Repo name or GitHub URL fragment (e.g. 'juice-shop' or 'Chai80/juice-shop').",
    )

    parser.add_argument(
        "--repo-name",
        dest="repo_name",
        required=False,
        help="Override the repository name used for output paths / normalized file name (useful for suite cases).",
    )
    parser.add_argument(
        "--branch",
        dest="branch",
        required=False,
        help="Cloud mode: branch name to select when multi-branch scanning is enabled in Aikido.",
    )

    # Local mode inputs.
    parser.add_argument(
        "--repo-path",
        required=False,
        help="Local repository path (required for --mode local).",
    )
    parser.add_argument(
        "--repo-url", required=False, help="Optional repo URL (metadata only)."
    )
    parser.add_argument(
        "--repositoryname",
        required=False,
        help="Aikido Local Scanner repository name (defaults to repo URL/name).",
    )
    parser.add_argument(
        "--branchname",
        required=False,
        help="Aikido Local Scanner branch name (defaults to current git branch).",
    )
    parser.add_argument(
        "--scan-types",
        nargs="+",
        required=False,
        help="Local scanner scan types (e.g. code dependencies secrets iac). Defaults to tool default (all).",
    )
    parser.add_argument(
        "--fail-on",
        default="low",
        help="Run local scanner in gating mode; fail at/above this severity (default: low).",
    )
    parser.add_argument(
        "--gating-mode",
        default="release",
        choices=["release", "pr"],
        help="Local scanner gating mode (default: release).",
    )
    parser.add_argument(
        "--base-commit-id", required=False, help="PR gating base commit (optional)."
    )
    parser.add_argument(
        "--head-commit-id", required=False, help="PR gating head commit (optional)."
    )
    parser.add_argument(
        "--force-create-repository-for-branch",
        action="store_true",
        help="Local scanner: create a separate Aikido repo per branch.",
    )
    parser.add_argument(
        "--no-snippets",
        action="store_true",
        help="Local scanner: do not upload code snippets.",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Local scanner: enable debug output."
    )
    parser.add_argument(
        "--prefer-binary",
        action="store_true",
        help="Local scanner: prefer installed aikido-local-scanner binary over Docker.",
    )
    parser.add_argument(
        "--docker-image",
        required=False,
        help="Local scanner Docker image (default: aikidosecurity/local-scanner:latest).",
    )

    parser.add_argument(
        "--output-root",
        default="runs/aikido",
        help="Output root folder (default: runs/aikido)",
    )
    parser.add_argument(
        "--skip-trigger",
        action="store_true",
        help="Skip triggering a scan; export latest issues.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Note: cli_entry never exits non-zero just because issues were found.
    cli_entry(
        git_ref=args.git_ref,
        output_root=args.output_root,
        skip_trigger=args.skip_trigger,
        mode=args.mode,
        repo_path=args.repo_path,
        repo_url=args.repo_url,
        repositoryname=(args.repo_name or args.repositoryname),
        branch=args.branch,
        branchname=args.branchname,
        scan_types=args.scan_types,
        fail_on=args.fail_on,
        gating_mode=args.gating_mode,
        base_commit_id=args.base_commit_id,
        head_commit_id=args.head_commit_id,
        force_create_repository_for_branch=args.force_create_repository_for_branch,
        no_snippets=args.no_snippets,
        debug=args.debug,
        prefer_binary=args.prefer_binary,
        docker_image=args.docker_image,
    )


if __name__ == "__main__":
    main()
