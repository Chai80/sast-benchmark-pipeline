"""Compatibility wrapper.

Historically this module lived at ``pipeline.analysis.qa_calibration_runbook``.
It has since moved to ``.qa.qa_calibration_runbook``.

This file re-exports the public API to avoid breaking imports.
"""

from .qa.qa_calibration_runbook import *  # noqa: F401,F403
