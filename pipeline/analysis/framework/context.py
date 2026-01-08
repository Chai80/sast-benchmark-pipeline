from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Tuple


def _derive_suite_case_ids(out_dir: Path) -> Tuple[Optional[str], Optional[str]]:
    """Best-effort derive suite_id and case_id from v2 layout paths.

    Expected v2 layout:
      runs/suites/<suite_id>/cases/<case_id>/analysis/

    Returns (suite_id, case_id) if the path matches; otherwise (None, None).
    """
    try:
        # out_dir/.../<case_id>/analysis
        case_dir = out_dir.parent if out_dir.name == "analysis" else None
        if not case_dir:
            return None, None
        if case_dir.parent.name != "cases":
            return None, None
        suite_id = case_dir.parent.parent.name  # runs/suites/<suite_id>/cases
        case_id = case_dir.name
        if suite_id and case_id:
            return suite_id, case_id
    except Exception:
        return None, None
    return None, None


@dataclass(frozen=True)
class AnalysisContext:
    """Immutable analysis job packet.

    This object is intentionally small and *read-only* to avoid analysis code
    devolving into spaghetti state mutation.

    Attributes
    ----------
    repo_name:
        Logical repo name used in legacy layouts (runs/<tool>/<repo_name>/...).
        In suite layout this is often the same as case.runs_repo_name.
    tools:
        Tools included in this analysis run.
    runs_dir:
        Base runs directory. In v2/suite layout, this is usually:
          <case_dir>/tool_runs
        In v1/legacy layout, this is usually:
          <repo_root>/runs
    out_dir:
        Output directory for analysis artifacts. In v2/suite layout:
          <case_dir>/analysis
    tolerance:
        Line clustering tolerance when grouping locations.
    mode:
        Finding filter mode: "security" or "all".
    formats:
        Output formats to write, e.g. ("json", "csv").
    normalized_paths:
        Mapping of tool -> latest normalized JSON path for that tool.
        This is computed at runner startup so stages don't have to rediscover it.
    suite_id / case_id:
        Best-effort IDs derived from out_dir when running in v2 layout.
    config:
        Free-form knobs for experiments. Prefer explicit fields for stable
        behavior and reserve config for temporary toggles.
    """

    repo_name: str
    tools: Tuple[str, ...]
    runs_dir: Path
    out_dir: Path
    tolerance: int = 3
    mode: str = "security"
    formats: Tuple[str, ...] = ("json", "csv")
    normalized_paths: Mapping[str, Path] = field(default_factory=dict)

    suite_id: Optional[str] = None
    case_id: Optional[str] = None

    config: Mapping[str, Any] = field(default_factory=dict)

    @staticmethod
    def build(
        *,
        repo_name: str,
        tools: Sequence[str],
        runs_dir: Path,
        out_dir: Path,
        tolerance: int = 3,
        mode: str = "security",
        formats: Sequence[str] = ("json", "csv"),
        normalized_paths: Mapping[str, Path] | None = None,
        config: Mapping[str, Any] | None = None,
    ) -> "AnalysisContext":
        out_dir = Path(out_dir)
        suite_id, case_id = _derive_suite_case_ids(out_dir)
        return AnalysisContext(
            repo_name=str(repo_name),
            tools=tuple(tools),
            runs_dir=Path(runs_dir),
            out_dir=out_dir,
            tolerance=int(tolerance),
            mode=str(mode),
            formats=tuple(formats),
            normalized_paths=dict(normalized_paths or {}),
            suite_id=suite_id,
            case_id=case_id,
            config=dict(config or {}),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "repo_name": self.repo_name,
            "tools": list(self.tools),
            "runs_dir": str(self.runs_dir),
            "out_dir": str(self.out_dir),
            "tolerance": self.tolerance,
            "mode": self.mode,
            "formats": list(self.formats),
            "normalized_paths": {k: str(v) for k, v in (self.normalized_paths or {}).items()},
            "suite_id": self.suite_id,
            "case_id": self.case_id,
            "config": dict(self.config or {}),
        }
