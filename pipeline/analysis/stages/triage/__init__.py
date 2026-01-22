"""pipeline.analysis.stages.triage

Triage stages (cluster ranking + feature extraction).

This package is also the compatibility target for the legacy
`pipeline.analysis.stages.triage` module import.
"""

# Import side-effect: stage registration decorators.
from . import triage_queue  # noqa: F401
from . import triage_features  # noqa: F401

# Re-export common symbols for backwards compatibility.
from .triage_queue import (  # noqa: F401
    TRIAGE_QUEUE_FIELDNAMES,
    TRIAGE_QUEUE_SCHEMA_VERSION,
    rank_triage_rows,
    stage_triage,
)
from .triage_features import stage_triage_features  # noqa: F401

__all__ = [
    "triage_queue",
    "triage_features",
    "TRIAGE_QUEUE_FIELDNAMES",
    "TRIAGE_QUEUE_SCHEMA_VERSION",
    "rank_triage_rows",
    "stage_triage",
    "stage_triage_features",
]
