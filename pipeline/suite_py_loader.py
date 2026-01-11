"""pipeline.suite_py_loader

Compatibility wrapper.

Python suite-loader implementation now lives in :mod:`pipeline.suites.suite_py_loader`.
This module re-exports it so existing imports keep working.

New code should prefer :mod:`pipeline.suites.suite_py_loader`.
"""

from __future__ import annotations

from pipeline.suites.suite_py_loader import *  # noqa: F401,F403
