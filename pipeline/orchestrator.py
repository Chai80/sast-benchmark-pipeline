"""pipeline.orchestrator

Compatibility wrapper for pipeline entrypoints.

Historically this repo's top-level operational entrypoints lived directly in
this module:

- ``run_tools`` (scan / benchmark execution)
- ``run_analyze`` (analysis over existing normalized outputs)

As the codebase grew, this file became a large "composition root" mixing many
responsibilities. To keep behavior identical while improving navigability, the
implementations were split into focused modules:

- :mod:`pipeline.run_case` (case execution)
- :mod:`pipeline.analyze_mode` (analysis mode)

This module intentionally re-exports the public API so existing imports keep
working:

.. code-block:: python

    from pipeline.orchestrator import RunRequest, AnalyzeRequest, run_tools, run_analyze
"""

from __future__ import annotations

from pipeline.analyze_mode import AnalyzeRequest, run_analyze
from pipeline.run_case import RunRequest, run_tools

__all__ = [
    "AnalyzeRequest",
    "RunRequest",
    "run_analyze",
    "run_tools",
]
