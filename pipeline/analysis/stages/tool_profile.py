"""Compatibility shim.

This module moved in PR2.

Prefer importing from `.benchmark.tool_profile`.
"""

from .benchmark.tool_profile import *  # noqa: F401,F403
