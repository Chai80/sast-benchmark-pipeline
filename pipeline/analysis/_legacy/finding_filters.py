"""Legacy import shim.

This module moved to `pipeline.analysis.utils.filters`.

Kept for backward compatibility so older imports and `python -m pipeline.analysis.<module>`
commands keep working during the refactor.
"""

from pipeline.analysis.utils.filters import *  # type: ignore

