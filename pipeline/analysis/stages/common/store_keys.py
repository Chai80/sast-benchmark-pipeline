from __future__ import annotations

"""pipeline.analysis.stages.common.store_keys

Central definitions for ArtifactStore keys.

Why this exists
---------------
Many stages communicate by reading/writing intermediate results in an
:class:`~pipeline.analysis.framework.ArtifactStore`. If every stage hardcodes
string keys (e.g. ``"location_clusters"``), small typos can silently break the
pipeline and refactors become painful.

These constants do **not** change runtime behavior; they simply centralize and
document the set of keys used across stages.
"""


class StoreKeys:
    # Shared intermediate artifacts
    FINDINGS_BY_TOOL = "findings_by_tool"
    LOCATION_ITEMS = "location_items"
    LOCATION_CLUSTERS = "location_clusters"
    SCOPE_FILTER_COUNTS = "scope_filter_counts"

    # Stage outputs cached in-store (used by reporting packs)
    OVERVIEW_REPORT = "overview_report"
    TOOL_PROFILE_ROWS = "tool_profile_rows"
    LOCATION_MATRIX_ROWS = "location_matrix_rows"
    HOTSPOT_MATRIX_ROWS = "hotspot_matrix_rows"
    PAIRWISE_ROWS = "pairwise_rows"
    TAXONOMY_ROWS = "taxonomy_rows"
    TRIAGE_ROWS = "triage_rows"
    CONSENSUS_ROWS = "consensus_rows"
    CONSENSUS_SUMMARY = "consensus_summary"

    # GT scoring stage
    GT_SCORE_ROWS = "gt_score_rows"
    GT_SCORE_SUMMARY = "gt_score_summary"
    GT_GAP_ROWS = "gt_gap_rows"

    # Taxonomy stage cache
    CWE_TO_OWASP_MAP = "cwe_to_owasp_map"

    # Diagnostics
    DIAGNOSTICS_SCHEMA = "diagnostics_schema"
    DIAGNOSTICS_EMPTY_RUNS = "diagnostics_empty_runs"
    DIAGNOSTICS_CASE_CONTEXT = "diagnostics_case_context"

    # Reporting packs
    BENCHMARK_PACK = "benchmark_pack"
    HOTSPOT_DRILLDOWN_PACK = "hotspot_drilldown_pack"
