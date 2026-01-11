"""pipeline.suite_definition

Compatibility wrapper.

Suite plan dataclasses and YAML helpers now live in :mod:`pipeline.suites.suite_definition`.
This module re-exports them so existing imports keep working.

New code should prefer :mod:`pipeline.suites.suite_definition`.
"""

from __future__ import annotations

from pipeline.suites.suite_definition import *  # noqa: F401,F403
