"""pipeline.analysis.stages.benchmark

Benchmark / analysis stages (non-GT).
"""

# Import side-effect: stage registration decorators.
from . import overview  # noqa: F401
from . import tool_profile  # noqa: F401
from . import location_matrix  # noqa: F401
from . import hotspot_matrix  # noqa: F401
from . import pairwise  # noqa: F401
from . import taxonomy  # noqa: F401
from . import consensus  # noqa: F401

__all__ = [
    "overview",
    "tool_profile",
    "location_matrix",
    "hotspot_matrix",
    "pairwise",
    "taxonomy",
    "consensus",
]
