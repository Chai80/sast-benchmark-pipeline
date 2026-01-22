"""Compatibility wrapper.

Historically this module lived at ``pipeline.analysis.suite_triage_eval``.
It has since moved to ``.suite.suite_triage_eval``.

This file re-exports the public API to avoid breaking imports.
"""

from .suite.suite_triage_eval import *  # noqa: F401,F403
