"""Legacy import shim.

This module moved to `pipeline.analysis.utils.signatures`.

Kept for backward compatibility so older imports and `python -m pipeline.analysis.<module>`
commands keep working during the refactor.
"""

from pipeline.analysis.utils.signatures import *  # type: ignore

