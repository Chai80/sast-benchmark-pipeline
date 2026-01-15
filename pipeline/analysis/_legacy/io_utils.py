"""Legacy import shim.

This module moved to `pipeline.analysis.io.write_artifacts`.

Kept for backward compatibility so older imports and `python -m pipeline.analysis.<module>`
commands keep working during the refactor.
"""

from pipeline.analysis.io.write_artifacts import *  # type: ignore

