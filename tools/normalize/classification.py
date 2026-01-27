"""Compatibility wrapper for normalization classification helpers.

Historically, the shared classification helpers lived under ``tools.normalize``.

To keep ``tools`` as a leaf executor package (and avoid higher-level orchestration
code importing from ``tools``), the canonical implementation now lives in the
neutral ``sast_benchmark`` layer:

    ``sast_benchmark.normalize.classification``

This module remains as a thin re-export so existing imports keep working.
"""

from sast_benchmark.normalize.classification import (
    infer_language,
    normalize_language,
    normalize_severity,
    resolve_owasp_and_cwe,
    strip_sentinel_values,
)

__all__ = [
    "infer_language",
    "normalize_language",
    "normalize_severity",
    "resolve_owasp_and_cwe",
    "strip_sentinel_values",
]
