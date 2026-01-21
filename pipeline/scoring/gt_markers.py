from __future__ import annotations

"""pipeline.scoring.gt_markers

Compatibility shim.

GT marker parsing is part of the *core* `sast_benchmark` namespace so both
execution and analysis can depend on it without creating circular imports.

Prefer importing from:
  - `sast_benchmark.gt.markers`

This module remains for backwards compatibility with older code paths.
"""

from sast_benchmark.gt.markers import extract_gt_markers  # re-export
