"""pipeline.analysis.suite.suite_compare_report

Suite-to-suite drift comparison.

This module is kept as a thin aggregator for compatibility. The implementation
lives under :mod:`pipeline.analysis.suite.compare`.
"""

from __future__ import annotations

from pipeline.analysis.suite.compare.load import SuiteArtifacts
from pipeline.analysis.suite.compare.report import (
    SUITE_COMPARE_REPORT_SCHEMA_V1,
    build_suite_compare_report,
)

__all__ = [
    "SUITE_COMPARE_REPORT_SCHEMA_V1",
    "SuiteArtifacts",
    "build_suite_compare_report",
]
