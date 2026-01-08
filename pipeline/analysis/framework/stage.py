from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from .context import AnalysisContext
from .store import ArtifactStore

StageFunc = Callable[[AnalysisContext, ArtifactStore], Optional[Dict[str, Any]]]


@dataclass
class StageResult:
    """Execution record for one stage."""

    name: str
    ok: bool
    started_at: str
    finished_at: str

    summary: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    warnings: list[str] = field(default_factory=list)
    artifacts: Dict[str, str] = field(default_factory=dict)
