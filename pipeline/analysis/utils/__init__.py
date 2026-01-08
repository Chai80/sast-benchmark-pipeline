"""pipeline.analysis.utils

Small tool-agnostic helpers used by multiple analysis stages:
- finding filters (security vs all)
- path normalization
- location signatures / clustering helpers

"""

from .filters import filter_findings, is_security_finding
from .path_norm import normalize_file_path
from .signatures import location_key, cluster_locations

__all__ = [
    "filter_findings",
    "is_security_finding",
    "normalize_file_path",
    "location_key",
    "cluster_locations",
]
