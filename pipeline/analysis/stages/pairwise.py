"""Compatibility shim.

This module moved in PR2.

Prefer importing from `.benchmark.pairwise`.
"""

from .benchmark.pairwise import *  # noqa: F401,F403
