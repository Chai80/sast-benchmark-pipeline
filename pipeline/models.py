"""pipeline.models

Lightweight data structures used across the pipeline.

Why this exists
---------------
The CLI and orchestration code historically passed many loosely-related values
(repo_url, repo_path, suite_id, output_root, etc.) as individual arguments.
That tends to grow into "spaghetti" as features are added.

These dataclasses provide a small, explicit vocabulary for:
- what is being scanned (RepoSpec)
- where results are written (SuiteSpec)
- how a target is identified within a suite (CaseSpec)

They are intentionally minimal and can be extended later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class RepoSpec:
    """Identify a scan target.

    Exactly one of these should typically be set, but we keep this permissive
    because some tools may need both a repo_url (for identity) and repo_path
    (for local scanning).
    """

    repo_key: Optional[str] = None
    repo_url: Optional[str] = None
    repo_path: Optional[str] = None

    def describe(self) -> str:
        if self.repo_key:
            return f"repo_key:{self.repo_key}"
        if self.repo_path:
            return f"repo_path:{self.repo_path}"
        if self.repo_url:
            return f"repo_url:{self.repo_url}"
        return "repo:unknown"


@dataclass(frozen=True)
class SuiteSpec:
    """A suite run (one experiment instance)."""

    suite_root: Path
    suite_id: str


@dataclass(frozen=True)
class CaseSpec:
    """A single case inside a suite.

    Notes
    -----
    - case_id is the stable identifier used for folders and DB ingestion.
    - runs_repo_name is the per-repo folder name scanners may use in legacy
      layouts or filenames.
    """

    case_id: str
    runs_repo_name: str
    label: str
    repo: RepoSpec

    branch: Optional[str] = None
    commit: Optional[str] = None

    # Optional benchmark track (e.g. "sast", "sca", "iac", "secrets").
    # Used to scope scanner execution and GT scoring when you mix tracks.
    track: Optional[str] = None
    tags: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolRunSpec:
    """One tool execution within a case.

    This is a small record used for manifests/export. It intentionally does not
    embed full finding payloads.
    """

    tool: str
    run_id: str
    run_dir: Path
    exit_code: int
    command: str
    started: Optional[str] = None
    finished: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)
