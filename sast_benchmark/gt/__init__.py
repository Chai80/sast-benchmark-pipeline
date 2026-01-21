"""sast_benchmark.gt

Ground-truth (GT) helpers.

This package intentionally lives under the *core* `sast_benchmark` namespace so
both execution (suite materialization) and analysis can depend on a single,
stable implementation without creating circular / "spaghetti" imports.

Design rule
-----------
Higher-level layers (CLI, pipeline orchestration, analysis stages) may import
from `sast_benchmark.gt`, but `sast_benchmark.gt` must not import from those
layers.
"""
