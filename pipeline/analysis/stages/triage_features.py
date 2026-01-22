"""Compatibility shim.

This module moved in PR2.

Prefer importing from `.triage.triage_features`.
"""

from .triage.triage_features import *  # noqa: F401,F403
