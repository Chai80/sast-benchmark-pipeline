"""pipeline.analysis

Analysis stages for the SAST benchmarking pipeline.

High level
----------
- Scanners write raw + normalized outputs (see tools/scan_*.py)
- Analysis reads normalized outputs and produces comparative artifacts (JSON/CSV)

This package is intentionally filesystem-first (no DB required), but outputs are
structured so they can be ingested into a database later.

Key entrypoints
--------------
- :mod:`pipeline.analysis.runner` — programmatic analysis runner
- :mod:`pipeline.analysis.analyze_suite` — legacy CLI entrypoint (`python -m ...`)

Subpackages
-----------
- io/      : discovery + artifact read/write helpers
- utils/   : pure helpers (filters, normalization, signatures)
- stages/  : analysis stages (overview, matrices, taxonomy, triage)
- exports/ : packers/exporters (benchmark pack, drilldown)
"""
