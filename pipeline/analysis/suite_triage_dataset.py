"""Compatibility wrapper.

Historically this module lived at ``pipeline.analysis.suite_triage_dataset``.
It has since moved to ``.suite.suite_triage_dataset``.

This file re-exports the public API to avoid breaking imports.
"""

from .suite.suite_triage_dataset import *  # noqa: F401,F403
