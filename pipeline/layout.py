"""pipeline.layout

Compatibility wrapper.

Suite/case layout helpers now live in :mod:`pipeline.suites.layout`.
This module remains as a thin shim for backwards compatibility.

New code should prefer :mod:`pipeline.suites.layout`.
"""

from __future__ import annotations

from pipeline.suites.layout import *  # noqa: F401,F403
