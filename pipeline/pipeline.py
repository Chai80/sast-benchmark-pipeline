"""pipeline.pipeline

This module defines a *single, high-level* object that represents this repo's
primary capabilities.

Why this exists
---------------
Today the repo's behavior is implemented across multiple modules:

- :mod:`pipeline.orchestrator` contains the operational entrypoints
  (run tools, run analysis).
- :mod:`pipeline.core` contains command building rules.
- :mod:`pipeline.analysis.*` contains cross-tool analytics.

That separation is good internally, but it's not a great "front door" for
callers (CLI, scripts, notebooks, CI runners). Callers end up importing and
wiring multiple modules directly, which can gradually turn the CLI into a
god-file.

The :class:`~pipeline.pipeline.SASTBenchmarkPipeline` facade gives the repo one
obvious entrypoint with a small API:

- ``run(...)``: run one or more scanners for a case (scan/benchmark)
- ``analyze(...)``: analyze existing normalized outputs

Implementation note
-------------------
In the first iteration, this facade is intentionally thin: it delegates to
existing orchestrator functions without changing behavior. That keeps the change
low-risk while creating a stable place to hang future refactors.
"""

from __future__ import annotations

from collections.abc import Callable

from pipeline.orchestrator import AnalyzeRequest, RunRequest, run_analyze, run_tools


class SASTBenchmarkPipeline:
    """High-level facade over the pipeline.

    Callers should prefer using this object (built via :func:`pipeline.wiring.build_pipeline`)
    rather than importing low-level modules directly.
    """

    def __init__(
        self,
        *,
        run_fn: Callable[[RunRequest], int] = run_tools,
        analyze_fn: Callable[[AnalyzeRequest], int] = run_analyze,
    ) -> None:
        self._run_fn = run_fn
        self._analyze_fn = analyze_fn

    def run(self, req: RunRequest) -> int:
        """Run one or more scanners for a single case.

        This is the shared implementation for "scan" and "benchmark" modes.
        """
        return int(self._run_fn(req))

    def analyze(self, req: AnalyzeRequest) -> int:
        """Run analysis over existing normalized runs (suite/case aware)."""
        return int(self._analyze_fn(req))
