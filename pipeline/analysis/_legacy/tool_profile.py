"""Legacy import shim.

This module moved to `pipeline.analysis.stages.tool_profile`.

Kept for backward compatibility so older imports and `python -m pipeline.analysis.<module>`
commands keep working during the refactor.
"""

from pipeline.analysis.stages.tool_profile import *  # type: ignore


if __name__ == "__main__":  # pragma: no cover
    from pipeline.analysis.stages.tool_profile import main as _main  # type: ignore
    _main()
