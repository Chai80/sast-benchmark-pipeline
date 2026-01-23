"""pipeline.execution.model

Shared data structures for case execution.

The execution layer is split into:

* :mod:`pipeline.execution.plan`   – pure planning (what to run)
* :mod:`pipeline.execution.runner` – subprocess execution (side effects)
* :mod:`pipeline.execution.record` – filesystem receipts/manifests (side effects)

These dataclasses intentionally contain no heavy side effects so they can be
used freely across the planner/runner/recorder.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pipeline.models import CaseSpec


def now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""

    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class RunCaseRequest:
    """Parameters for running one case (scan or benchmark)."""

    invocation_mode: str  # "scan" | "benchmark"
    case: CaseSpec
    repo_id: str

    scanners: Sequence[str]

    # suite writing
    suite_root: Path

    # configuration labeling (recorded in run receipts; does not change tool settings)
    profile: str = "default"

    suite_id: Optional[str] = None
    use_suite: bool = True

    # execution
    dry_run: bool = False
    quiet: bool = False

    # post-processing
    skip_analysis: bool = False
    tolerance: int = 3
    gt_tolerance: int = 0
    gt_source: str = "auto"
    analysis_filter: str = "security"

    # scope filtering (analysis only)
    exclude_prefixes: Sequence[str] = ()
    include_harness: bool = False

    # tool overrides
    sonar_project_key: Optional[str] = None
    aikido_git_ref: Optional[str] = None

    # manifest provenance
    argv: Optional[Sequence[str]] = None
    python_executable: Optional[str] = None


@dataclass(frozen=True)
class GitContext:
    """Best-effort git context for the scanned repo checkout."""

    branch: Optional[str]
    commit: Optional[str]


@dataclass(frozen=True)
class ToolInvocation:
    """A planned tool command invocation."""

    scanner: str
    cmd: List[str]

    @property
    def command_str(self) -> str:
        return " ".join(self.cmd)


@dataclass(frozen=True)
class ToolExecution:
    """The result of executing a tool invocation."""

    invocation: ToolInvocation
    exit_code: int
    started: str
    finished: str

    @property
    def cmd(self) -> List[str]:
        return list(self.invocation.cmd)

    @property
    def command_str(self) -> str:
        return self.invocation.command_str


@dataclass(frozen=True)
class RunCaseResult:
    """Optional richer result for callers that need more than an exit code."""

    exit_code: int
    suite_id: Optional[str] = None
    suite_dir: Optional[str] = None
    case_dir: Optional[str] = None

    # Best-effort paths to commonly needed artifacts.
    case_manifest: Optional[str] = None
    suite_summary: Optional[str] = None
