"""Compatibility shim.

This module moved in PR2.

Prefer importing from `.gt.gt_score`.
"""

from .gt.gt_score import *  # noqa: F401,F403
