"""pipeline.analysis.io

Filesystem IO helpers for analysis.

These modules are intentionally small wrappers around:
- discovering the latest normalized runs per tool
- reading per-run metadata where present
- writing analysis artifacts (csv/json)

"""

from .discovery import find_latest_normalized_json, find_latest_run_dir
from .meta import read_json_if_exists
from .write_artifacts import write_json, write_csv

__all__ = [
    "find_latest_normalized_json",
    "find_latest_run_dir",
    "read_json_if_exists",
    "write_json",
    "write_csv",
]
