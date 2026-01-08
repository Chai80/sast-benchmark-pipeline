"""pipeline.analysis.io.discovery

Compatibility wrapper around the canonical layout helpers.

Historically the analysis layer maintained its own implementation for finding
the "latest" run directory and locating the corresponding normalized output.
That created duplicated heuristics across:

* tools/* (writing runs)
* pipeline/layout.py (suite/case helper)
* pipeline/analysis/io/discovery.py (analysis reader)

The canonical implementation now lives in :mod:`sast_benchmark.io.layout`.
This module remains as a thin shim to avoid churn in the analysis code.
"""

from __future__ import annotations

from pathlib import Path

from sast_benchmark.io.layout import find_latest_normalized_json, find_latest_run_dir

__all__ = [
    "find_latest_run_dir",
    "find_latest_normalized_json",
]
