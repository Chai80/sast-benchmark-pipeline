"""Legacy import shim.

This module moved to `pipeline.scoring.gt_scorer`.

Kept for backward compatibility so older imports and `python -m pipeline.analysis.<module>`
commands keep working during the refactor.
"""

from pipeline.scoring.gt_scorer import *  # type: ignore


if __name__ == "__main__":  # pragma: no cover
    from pipeline.scoring.gt_scorer import main as _main  # type: ignore
    _main()
