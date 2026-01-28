"""CLI argument builder modules.

The top-level :mod:`sast_cli` is intentionally kept thin.  As the CLI grows,
we register groups of flags via small "arg builder" functions housed here.

Each module exposes a single public function:

- :func:`cli.args.base.add_base_args`
- :func:`cli.args.suite.add_suite_args`
- :func:`cli.args.analyze.add_analyze_args`
- :func:`cli.args.import_mode.add_import_mode_args`
- :func:`cli.args.tool_overrides.add_tool_override_args`

This reduces merge conflicts and makes it easier to evolve specific modes
without turning :func:`sast_cli.parse_args` into a god function.
"""

from __future__ import annotations

__all__ = [
    "base",
    "suite",
    "analyze",
    "import_mode",
    "tool_overrides",
]
