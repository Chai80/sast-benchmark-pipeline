"""SonarCloud integration modules.

Split into:
  - api.py      : all HTTP calls to SonarCloud
  - rules.py    : pure parsing of /api/rules/show into classification fields
  - normalize.py: base normalization + optional enrichment glue
  - types.py    : small shared data structures

Orchestration implementation lives in tools/sonar/runner.py.

The stable script entrypoint used by the pipeline remains:
  tools/scan_sonar.py
"""
