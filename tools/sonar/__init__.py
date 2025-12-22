"""SonarCloud integration modules.

Split into:
  - api.py      : all HTTP calls to SonarCloud
  - rules.py    : pure parsing of /api/rules/show into classification fields
  - normalize.py: base normalization + optional enrichment glue
  - types.py    : small shared data structures

The scan_sonar.py script acts as the orchestration layer.
"""
