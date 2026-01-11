"""pipeline.run_case

Compatibility wrapper.

The implementation of case execution lives in :mod:`pipeline.execution.run_case`.
This module re-exports the public API so existing imports keep working.
"""

from __future__ import annotations

from pipeline.execution.run_case import RunRequest, run_tools

__all__ = [
    "RunRequest",
    "run_tools",
]
