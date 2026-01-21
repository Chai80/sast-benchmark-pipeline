"""Suite-mode CLI command (multi-case orchestrator).

Historically this command lived in a single module: ``cli/commands/suite.py``.
It has been refactored into a package to keep responsibilities separated
(materializing suite definitions vs QA calibration helpers vs execution).

The public import surface remains stable:

    from cli.commands.suite import run_suite_mode

"""

from __future__ import annotations

from .cmd import run_suite_mode

__all__ = [
    "run_suite_mode",
]
