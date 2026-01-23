"""pipeline.analysis.compute

Pure-ish computation helpers used by analysis stages.

Design goal
-----------
Keep `pipeline.analysis.stages.*` modules focused on orchestration:
  - read inputs from ctx/store
  - call compute helpers
  - write artifacts

This package intentionally contains no stage registration decorators.
"""

from __future__ import annotations
