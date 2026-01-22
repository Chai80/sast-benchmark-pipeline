"""pipeline.analysis

Analysis stages for the SAST benchmarking pipeline.

High level
----------
- Scanners write raw + normalized outputs (see tools/scan_*.py)
- Analysis reads raw + normalized outputs and produces comparative artifacts (JSON/CSV)

This package is intentionally filesystem-first (no DB required), but outputs are
structured so they can be ingested into a database later.

Key entrypoints
--------------
- :mod:`pipeline.analysis.runner` — programmatic analysis runner
- :mod:`pipeline.analysis.analyze_suite` — legacy CLI entrypoint (`python -m ...`)

Subpackages
-----------
- suite/   : suite-level jobs (calibration, eval, reports, tolerance sweep)
- qa/      : QA runbooks, manifests, and checklists
- io/      : discovery + artifact read/write helpers
- utils/   : pure helpers (filters, normalization, signatures)
- stages/  : analysis stages (overview, matrices, taxonomy, triage)
- exports/ : packers/exporters (benchmark pack, drilldown)
"""

# Backward-compat: in rare cases we may relocate compatibility shims into
# pipeline/analysis/_legacy/ and extend the package search path here.
# Today, compatibility is provided by thin re-export modules under pipeline/analysis/.

from pathlib import Path

_legacy_dir = Path(__file__).resolve().parent / "_legacy"
if _legacy_dir.is_dir():
    __path__.append(str(_legacy_dir))
