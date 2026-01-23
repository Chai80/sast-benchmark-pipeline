"""Compatibility shim.

This module moved in PR2.

Prefer importing from `.diagnostics.case_context`.
"""

from .diagnostics.case_context import *  # noqa: F401,F403
