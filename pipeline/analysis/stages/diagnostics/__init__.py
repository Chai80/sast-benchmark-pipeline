"""pipeline.analysis.stages.diagnostics

Diagnostic stages (schema checks, empty runs, suite context).

This package replaces the legacy `pipeline.analysis.stages.diagnostics` module.
"""

# Import side-effect: stage registration decorators.
from . import schema  # noqa: F401
from . import empty_runs  # noqa: F401
from . import case_context  # noqa: F401

# Re-export common stage functions for backwards compatibility.
from .schema import stage_diagnostics_schema  # noqa: F401
from .empty_runs import stage_diagnostics_empty  # noqa: F401
from .case_context import stage_diagnostics_case_context  # noqa: F401

__all__ = [
    "schema",
    "empty_runs",
    "case_context",
    "stage_diagnostics_schema",
    "stage_diagnostics_empty",
    "stage_diagnostics_case_context",
]
