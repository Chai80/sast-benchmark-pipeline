from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Tuple

from pipeline.analysis.utils.path_norm import normalize_exclude_prefixes


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
    gt_tolerance:
        Line overlap tolerance used ONLY for GT scoring (gt_score stage).
    mode:
        Finding filter mode: "security" or "all".
    exclude_prefixes:
        Repo-relative path prefixes to exclude across ALL analysis stages.
        Comparisons use normalized, repo-relative POSIX-like paths.

        In v2/suite layout, benchmark harness paths under "benchmark/" are
        excluded by default unless include_harness is True.
    include_harness:
        If True, do not apply the suite-layout default harness exclusion.
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

    # Clustering tolerance (location_matrix / triage UX)
    tolerance: int = 3

    # GT scoring tolerance (gt_score only)
    gt_tolerance: int = 0

    mode: str = "security"

    # Scope filtering
    exclude_prefixes: Tuple[str, ...] = ()
    include_harness: bool = False

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
        gt_tolerance: int = 0,
        mode: str = "security",
        exclude_prefixes: Sequence[str] | None = None,
        include_harness: bool = False,
        formats: Sequence[str] = ("json", "csv"),
        normalized_paths: Mapping[str, Path] | None = None,
        config: Mapping[str, Any] | None = None,
    ) -> "AnalysisContext":
        out_dir = Path(out_dir)
        suite_id, case_id = _derive_suite_case_ids(out_dir)

        # Normalize user-provided exclude prefixes.
        normalized = list(normalize_exclude_prefixes(exclude_prefixes))

        # Suite layout default: exclude harness noise under benchmark/ unless explicitly included.
        # This keeps SCA/SAST tools from surfacing benchmark harness scripts as top hotspots.
        if suite_id and case_id and not include_harness:
            default_harness_prefix = "benchmark"
            if default_harness_prefix not in normalized:
                normalized.append(default_harness_prefix)

        return AnalysisContext(
            repo_name=str(repo_name),
            tools=tuple(tools),
            runs_dir=Path(runs_dir),
            out_dir=out_dir,
            tolerance=int(tolerance),
            gt_tolerance=max(0, int(gt_tolerance)),
            mode=str(mode),
            exclude_prefixes=tuple(normalized),
            include_harness=bool(include_harness),
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
            "gt_tolerance": self.gt_tolerance,
            "mode": self.mode,
            "exclude_prefixes": list(self.exclude_prefixes or ()),
            "include_harness": bool(self.include_harness),
            "formats": list(self.formats),
            "normalized_paths": {k: str(v) for k, v in (self.normalized_paths or {}).items()},
            "suite_id": self.suite_id,
            "case_id": self.case_id,
            "config": dict(self.config or {}),
        }
