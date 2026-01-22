from __future__ import annotations

"""pipeline.analysis.stages._shared

Backwards-compatible re-exports for helpers historically defined in this module.

New code should prefer importing from :mod:`pipeline.analysis.stages.common`.

This indirection allows us to keep public import paths stable while gradually
cleaning up the architecture.
"""

from .common.findings import load_findings_by_tool, load_normalized_json
from .common.locations import build_location_items, ensure_location_clusters
from .common.severity import max_severity, severity_rank

__all__ = [
    "load_normalized_json",
    "load_findings_by_tool",
    "build_location_items",
    "ensure_location_clusters",
    "severity_rank",
    "max_severity",
]
