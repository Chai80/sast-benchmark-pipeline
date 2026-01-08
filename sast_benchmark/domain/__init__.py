"""sast_benchmark.domain

Domain objects that form the *contract* between pipeline stages.

Key idea
--------
Tools produce raw outputs in tool-specific formats. The benchmark pipeline
normalizes those into a tool-agnostic representation so that analysis/scoring
does not need to know vendor quirks.
"""

from __future__ import annotations

from .finding import FindingNormalized, OwaspTop10Block

__all__ = [
    "FindingNormalized",
    "OwaspTop10Block",
]
