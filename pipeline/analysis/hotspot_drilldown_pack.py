"""Legacy import shim.

This module moved to `pipeline.analysis.exports.drilldown_pack`.

Kept for backward compatibility so older imports and `python -m pipeline.analysis.<module>`
commands keep working during the refactor.
"""

from pipeline.analysis.exports.drilldown_pack import *  # type: ignore


if __name__ == "__main__":  # pragma: no cover
    from pipeline.analysis.exports.drilldown_pack import main as _main  # type: ignore
    _main()
