"""pipeline.analysis.framework.pipelines

Pipeline definitions (ordered stage lists).

This is intentionally small and declarative. To add a new analysis, implement a
stage and register it, then drop its name into a pipeline list.

Naming convention
-----------------
- benchmark_*: core benchmark analysis stages
- diagnostics_*: sanity checks / debugging stages
- reporting_*: packaging / human-readable outputs

"""

from __future__ import annotations

from typing import Dict, List

PIPELINES: Dict[str, List[str]] = {
    # Core cross-tool benchmark analysis
    "benchmark": [
        "diagnostics_case_context",
        "overview",
        "tool_profile",
        "location_matrix",
        "pairwise_agreement",
        "taxonomy",
        "triage_queue",
        "consensus_queue",
        "gt_score",
        # DS-friendly export (cluster feature table)
        "triage_features",
    ],

    # Optional diagnostics (not run by default)
    "diagnostics": [
        "diagnostics_case_context",
        "diagnostics_schema",
        "diagnostics_empty_runs",
    ],

    # Reporting / export stages
    "reporting": [
        "benchmark_pack",
        "hotspot_drilldown_pack",
    ],
}
