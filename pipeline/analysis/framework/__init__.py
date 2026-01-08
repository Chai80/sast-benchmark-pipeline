"""pipeline.analysis.framework

A small modular analysis framework.

Goals
-----
This is **scaffolding** for a stage-based analysis system:

- **AnalysisContext (ctx)**: an immutable job packet (IDs, paths, knobs)
- **ArtifactStore (store)**: an in-memory scratchpad to share intermediate results
- **Stages**: small, composable units of work
- **Pipelines**: ordered lists of stages (benchmark vs diagnostics vs reporting)

This lives alongside the legacy analysis entrypoints in :mod:`pipeline.analysis`
and is intended to enable incremental migration without breaking existing flows.

"""

from .context import AnalysisContext
from .store import ArtifactStore
from .stage import StageResult, StageFunc
from .registry import register_stage, get_stage, list_stages, StageDefinition
from .pipelines import PIPELINES
from .runner import run_pipeline, write_analysis_manifest

__all__ = [
    "AnalysisContext",
    "ArtifactStore",
    "StageResult",
    "StageFunc",
    "StageDefinition",
    "PIPELINES",
    "register_stage",
    "get_stage",
    "list_stages",
    "run_pipeline",
    "write_analysis_manifest",
]
