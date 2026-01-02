"""pipeline.analysis.finding_filters

Central place for tool-aware filtering decisions used by analysis stages.

Why this exists
---------------
We want location alignment and drilldown exports to operate on the *same*
set of findings. If each script re-implements filtering, the logic can drift
and you end up with confusing results ("why is this row in the matrix but
missing from the drilldown pack?").

This module keeps that logic in one place.

Modes
-----
- mode="security" (default): keep security-relevant findings and drop obvious noise
  where a tool is known to emit lots of non-security items.
- mode="all": keep everything (as long as it has a location elsewhere in the pipeline).

Note: This is intentionally lightweight and conservative. It's not trying to be
a full taxonomy or policy engine.
"""

from __future__ import annotations

from typing import Any, List, Mapping, Sequence


def filter_findings(tool: str, findings: Sequence[Mapping[str, Any]], *, mode: str) -> List[Mapping[str, Any]]:
    """Return a filtered list of findings for a given tool and mode.

    This function should be used anywhere you need "the same findings" across
    scripts (e.g., hotspot_location_matrix + hotspot_drilldown_pack).
    """

    if mode == "all":
        return list(findings)

    out: List[Mapping[str, Any]] = []
    for f in findings:
        # Sonar emits CODE_SMELL/Bug items in addition to security. Keep only security by default.
        if tool == "sonar":
            t = (f.get("vendor") or {}).get("raw_result", {}).get("type")
            if t not in ("VULNERABILITY", "SECURITY_HOTSPOT"):
                continue

        # Aikido mixes SAST, secrets, OSS, etc. Exclude OSS by default for code-location comparison.
        if tool == "aikido":
            t = (f.get("vendor") or {}).get("raw_result", {}).get("type")
            if t == "open_source":
                continue

        out.append(f)

    return out
