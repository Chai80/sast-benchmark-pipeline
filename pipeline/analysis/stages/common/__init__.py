"""pipeline.analysis.stages.common

Shared helpers used by analysis stages.

This package intentionally contains **no stage registration** and should be
safe to import from anywhere inside the analysis subsystem.

It exists to keep individual stage modules small and to avoid copy/pasting
common store wiring.
"""

from .store_keys import StoreKeys

__all__ = [
    "StoreKeys",
]
