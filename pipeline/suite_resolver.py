"""pipeline.suite_resolver

Compatibility wrapper.

Suite resolution boundary now lives in :mod:`pipeline.suites.suite_resolver`.
This module re-exports it so existing imports keep working.

New code should prefer :mod:`pipeline.suites.suite_resolver`.
"""

from __future__ import annotations

from pipeline.suites.suite_resolver import *  # noqa: F401,F403
