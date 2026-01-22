"""Compatibility wrapper.

Historically this module lived at ``pipeline.analysis.suite_triage_calibration``.
It has since moved to ``.suite.suite_triage_calibration``.

This file re-exports the public API to avoid breaking imports.
"""

from .suite.suite_triage_calibration import *  # noqa: F401,F403
