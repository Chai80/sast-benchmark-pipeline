"""Legacy import shim.

This module moved to `pipeline.analysis.stages.triage`.

Kept for backward compatibility so older imports and `python -m pipeline.analysis.<module>`
commands keep working during the refactor.
"""

from pipeline.analysis.stages.triage import *  # type: ignore


if __name__ == "__main__":  # pragma: no cover
    from pipeline.analysis.stages.triage import main as _main  # type: ignore
    _main()
