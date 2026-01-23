"""pipeline.analysis.stages

Builtin analysis stages.

Importing this package registers builtin stages in the global registry.
"""

# Import side-effect: stage registration decorators.
from . import benchmark  # noqa: F401
from . import triage  # noqa: F401
from . import diagnostics  # noqa: F401
from . import gt  # noqa: F401

__all__ = [
    "benchmark",
    "triage",
    "diagnostics",
    "gt",
]
