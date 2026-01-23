"""cli.commands.suite.runbook_steps.model

Shared state for the suite runbook.

This module intentionally contains only lightweight dataclasses + simple
construction logic so step modules can depend on it without creating import
cycles.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from pipeline.core import ROOT_DIR as PIPELINE_ROOT_DIR
from pipeline.pipeline import SASTBenchmarkPipeline
from pipeline.suites.bundles import anchor_under_repo_root
from pipeline.suites.suite_definition import SuiteAnalysisDefaults
from pipeline.suites.suite_resolver import SuiteInputProvenance


ROOT_DIR = PIPELINE_ROOT_DIR


@dataclass(frozen=True)
class SuiteFlags:
    """Normalized mode flags derived from CLI args."""

    qa_mode: bool = False
    qa_no_reanalyze: bool = False


@dataclass
class GTToleranceSweepState:
    """Best-effort sweep/selection state for QA manifests."""

    enabled: bool = False
    candidates: List[int] = field(default_factory=list)
    report_csv: Optional[str] = None
    payload_json: Optional[str] = None
    selection_path: Optional[str] = None
    selection_warnings: List[str] = field(default_factory=list)

    payload: Optional[Dict[str, Any]] = None
    selection: Optional[Dict[str, Any]] = None

    # Policy inputs used when writing the selection file (populated at runtime).
    sweep_raw: Optional[str] = None
    auto_enabled: bool = False
    auto_min_fraction: float = 0.95


@dataclass
class SuiteRunContext:
    """Mutable context shared across suite runbook steps."""

    args: argparse.Namespace
    pipeline: SASTBenchmarkPipeline
    repo_registry: Dict[str, Dict[str, str]]
    suite_root: Path

    flags: SuiteFlags = field(default_factory=SuiteFlags)

    # Captured before any sweep/auto selection mutates args.
    gt_tolerance_initial: int = 0

    # Best-effort sweep/selection state (QA calibration).
    gt_sweep: GTToleranceSweepState = field(default_factory=GTToleranceSweepState)

    # Resolved run configuration (filled by resolve steps).
    suite_id: str = ""
    suite_dir: Optional[Path] = None
    scanners: List[str] = field(default_factory=list)
    tolerance: int = 0
    analysis_filter: str = ""
    skip_analysis: bool = False
    provenance: Optional[SuiteInputProvenance] = None
    analysis_defaults: Optional[SuiteAnalysisDefaults] = None

    # QA checklist result (filled best-effort).
    qa_checklist_pass: Optional[bool] = None

    @classmethod
    def from_args(
        cls,
        *,
        args: argparse.Namespace,
        pipeline: SASTBenchmarkPipeline,
        repo_registry: Dict[str, Dict[str, str]],
    ) -> "SuiteRunContext":
        """Create a context with stable paths and captured mode flags."""

        suite_root = anchor_under_repo_root(Path(args.suite_root).expanduser())

        flags = SuiteFlags(
            qa_mode=bool(getattr(args, "qa_calibration", False)),
            qa_no_reanalyze=bool(getattr(args, "qa_no_reanalyze", False)),
        )

        # Capture GT tolerance input *before* any sweep/auto-selection mutates args.
        gt_tolerance_initial = int(getattr(args, "gt_tolerance", 0) or 0)

        return cls(
            args=args,
            pipeline=pipeline,
            repo_registry=repo_registry,
            suite_root=suite_root,
            flags=flags,
            gt_tolerance_initial=gt_tolerance_initial,
            gt_sweep=GTToleranceSweepState(),
        )
