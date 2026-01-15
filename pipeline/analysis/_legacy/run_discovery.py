"""Legacy import shim.

This module moved to `pipeline.analysis.io.discovery`.

Kept for backward compatibility so older imports and `python -m pipeline.analysis.<module>`
commands keep working during the refactor.
"""

from pipeline.analysis.io.discovery import *  # type: ignore

