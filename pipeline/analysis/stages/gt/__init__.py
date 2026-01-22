"""pipeline.analysis.stages.gt

Ground-truth scoring stages.
"""

# Import side-effect: stage registration decorators.
from . import gt_score  # noqa: F401

__all__ = [
    "gt_score",
]
