"""Compatibility wrapper.

Historically this module lived at ``pipeline.analysis.gt_tolerance_sweep``.
It has since moved to ``.suite.gt_tolerance_sweep``.

This file re-exports the public API to avoid breaking imports.
"""

from .suite.gt_tolerance_sweep import *  # noqa: F401,F403
