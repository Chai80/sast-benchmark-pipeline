"""tools.normalize.classification

Compatibility shim.

The canonical implementation for classification helpers lives in
`sast_benchmark.normalize.classification`. Keep this module thin and
only re-export symbols that actually exist there.
"""

from __future__ import annotations

from sast_benchmark.normalize.classification import (
    OWASP_TOP_10_2017_NAMES,
    OWASP_TOP_10_2021_NAMES,
    normalize_cwe_id,
    normalize_owasp_top10_code,
    resolve_owasp_and_cwe,
)

__all__ = [
    "OWASP_TOP_10_2017_NAMES",
    "OWASP_TOP_10_2021_NAMES",
    "normalize_cwe_id",
    "normalize_owasp_top10_code",
    "resolve_owasp_and_cwe",
]
