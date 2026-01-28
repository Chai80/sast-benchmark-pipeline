"""pipeline.analysis.suite.triage_eval.compute

Computation entrypoints for suite-level triage evaluation.

This file is intentionally kept small.

Historically, the full implementation lived here and grew into a large module.
It has been split into focused submodules:

- :mod:`pipeline.analysis.suite.triage_eval.compute_impl`
- :mod:`pipeline.analysis.suite.triage_eval.compute_case_tables`
- :mod:`pipeline.analysis.suite.triage_eval.compute_macro_micro`
- :mod:`pipeline.analysis.suite.triage_eval.compute_deltas`
- :mod:`pipeline.analysis.suite.triage_eval.compute_helpers`
- :mod:`pipeline.analysis.suite.triage_eval.compute_types`

The public API remains stable:
- :func:`compute_triage_eval`
- :class:`TriageEvalComputeResult`
"""

from __future__ import annotations

from typing import Callable, Dict, List

from .compute_impl import compute_triage_eval
from .compute_types import TriageEvalComputeResult


RankFn = Callable[[List[Dict[str, str]]], List[Dict[str, str]]]

__all__ = [
    "RankFn",
    "TriageEvalComputeResult",
    "compute_triage_eval",
]
