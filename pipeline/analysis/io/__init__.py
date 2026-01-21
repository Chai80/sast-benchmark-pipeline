"""pipeline.analysis.io

Filesystem IO helpers for analysis.

These modules are intentionally small wrappers around:
- discovering the latest normalized runs per tool
- reading per-run metadata where present
- writing analysis artifacts (csv/json)

"""

from .case_index import build_case_index, write_case_index_json
from .config_receipts import (
    discover_config_receipt_paths,
    load_scanner_config,
    summarize_scanner_config,
)
from .discovery import find_latest_normalized_json, find_latest_run_dir
from .meta import read_json_if_exists
from .write_artifacts import write_csv, write_json

__all__ = [
    "build_case_index",
    "write_case_index_json",
    "discover_config_receipt_paths",
    "summarize_scanner_config",
    "load_scanner_config",
    "find_latest_normalized_json",
    "find_latest_run_dir",
    "read_json_if_exists",
    "write_json",
    "write_csv",
]
