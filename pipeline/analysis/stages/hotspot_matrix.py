"""Compatibility shim.

This module moved in PR2.

Prefer importing from `.benchmark.hotspot_matrix`.
"""

from .benchmark.hotspot_matrix import *  # noqa: F401,F403
