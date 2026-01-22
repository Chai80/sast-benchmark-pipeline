"""Compatibility shim.

This module moved in PR2.

Prefer importing from `.benchmark.consensus`.
"""

from .benchmark.consensus import *  # noqa: F401,F403
