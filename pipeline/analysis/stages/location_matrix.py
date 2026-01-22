"""Compatibility shim.

This module moved in PR2.

Prefer importing from `.benchmark.location_matrix`.
"""

from .benchmark.location_matrix import *  # noqa: F401,F403
