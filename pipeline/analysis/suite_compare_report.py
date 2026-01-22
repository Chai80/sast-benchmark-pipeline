"""Compatibility wrapper.

Historically this module lived at ``pipeline.analysis.suite_compare_report``.
It has since moved to ``.suite.suite_compare_report``.

This file re-exports the public API to avoid breaking imports.
"""

from .suite.suite_compare_report import *  # noqa: F401,F403
