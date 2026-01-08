"""pipeline.scoring

Scoring utilities (ground truth, metrics).

This package is intentionally minimal in this patch. It exists so the
compatibility shim :mod:`pipeline.analysis.gt_scorer` can import a stable
implementation.

"""

from .gt_scorer import score_locations, score_from_files

__all__ = ["score_locations", "score_from_files"]
