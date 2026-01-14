"""pipeline.analysis.stages

Builtin analysis stages.

Importing this package registers builtin stages in the global registry.
"""

# Import side-effect: stage registration decorators.
from . import overview  # noqa: F401
from . import tool_profile  # noqa: F401
from . import location_matrix  # noqa: F401
from . import hotspot_matrix  # noqa: F401
from . import pairwise  # noqa: F401
from . import taxonomy  # noqa: F401
from . import triage  # noqa: F401
from . import gt_score  # noqa: F401
from . import triage_features  # noqa: F401
from . import diagnostics  # noqa: F401
from . import case_context  # noqa: F401

__all__ = [
    "overview",
    "tool_profile",
    "location_matrix",
    "hotspot_matrix",
    "pairwise",
    "taxonomy",
    "triage",
    "gt_score",
    "triage_features",
    "diagnostics",
    "case_context",
]
