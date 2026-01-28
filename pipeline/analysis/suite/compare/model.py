"""pipeline.analysis.suite.compare.model

Small data models used by the suite-to-suite comparison helpers.

Keeping these in a dedicated module keeps :mod:`.load` focused on filesystem
parsing and allows other modules to type-check without importing the loaders.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class SuiteArtifacts:
    suite_id: str
    suite_dir: Path

    suite_json_path: Path
    suite_json: Optional[Dict[str, Any]]

    scanner_config: Dict[str, Any]

    qa_manifest_path: Optional[Path]
    qa_manifest: Optional[Dict[str, Any]]

    eval_summary_path: Optional[Path]
    eval_summary: Optional[Dict[str, Any]]

    dataset_csv: Optional[Path]
    tool_utility_csv: Optional[Path]
    calibration_json: Optional[Path]
    tool_marginal_csv: Optional[Path]


__all__ = ["SuiteArtifacts"]
