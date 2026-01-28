from __future__ import annotations

import argparse


def add_tool_override_args(parser: argparse.ArgumentParser) -> None:
    """Register tool-specific overrides (SonarCloud, Aikido, ...)."""

    # Sonar-specific
    parser.add_argument(
        "--sonar-project-key",
        help="(sonar only) Override SonarCloud project key. If omitted, we derive ORG_<repo_id>.",
    )

    # Aikido-specific
    parser.add_argument(
        "--aikido-git-ref",
        help=(
            "(aikido only) Override the git reference passed to scan_aikido.py as --git-ref. "
            "Use this when running aikido with --repo-path and no --repo-url (e.g., suite branch clones/worktrees). "
            "Example: Chai80/durinn-owasp2021-python-micro-suite"
        ),
    )
