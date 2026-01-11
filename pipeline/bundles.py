"""pipeline.bundles

Compatibility wrapper.

The suite/case filesystem layout implementation lives in :mod:`pipeline.suites.bundles`.
This module re-exports those helpers so existing imports keep working.

New code should prefer importing from :mod:`pipeline.suites`.
"""

from __future__ import annotations

from pipeline.suites.bundles import *  # noqa: F401,F403
