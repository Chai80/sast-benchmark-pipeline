"""pipeline.suite_definition

Optional YAML plan format for "suite mode" runs.

Why this exists
---------------
The CLI supports running a **suite** (one experiment instance) containing many
**cases** (repos / branches / worktrees). YAML is optional:

- If a YAML suite definition is provided, it acts as a *plan* (what to run).
- Regardless of YAML, the pipeline still writes suite.json / case.json / run.json
  as the ground-truth record of what actually ran.

This module is intentionally small and filesystem-first. It provides:
- dataclasses for the YAML schema
- load/dump helpers

Design goals
------------
- Backwards compatible: tolerate missing optional fields.
- Be permissive: allow simple case entries with just repo_url/repo_key.
- Avoid coupling to any specific scanner/tool.

"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


from pipeline.models import CaseSpec, RepoSpec


# ----------------------------
# YAML model
# ----------------------------

@dataclass(frozen=True)
class SuiteAnalysisDefaults:
    """Defaults for analysis behavior in suite mode."""

    skip: bool = False
    tolerance: int = 3
    filter: str = "security"  # security|all


@dataclass(frozen=True)
class SuiteCaseOverrides:
    """Per-case overrides for tool-specific knobs.

    These are intentionally optional and sparse. If you later add tool-specific
    settings, add them here without changing the core CaseSpec.
    """

    sonar_project_key: Optional[str] = None
    aikido_git_ref: Optional[str] = None


@dataclass(frozen=True)
class SuiteCase:
    """One case entry in a suite definition."""

    case: CaseSpec
    overrides: SuiteCaseOverrides = field(default_factory=SuiteCaseOverrides)


@dataclass(frozen=True)
class SuiteDefinition:
    """A complete suite definition (plan)."""

    suite_id: Optional[str] = None
    scanners: List[str] = field(default_factory=list)
    cases: List[SuiteCase] = field(default_factory=list)
    analysis: SuiteAnalysisDefaults = field(default_factory=SuiteAnalysisDefaults)

    # ----------------------------
    # Conversions
    # ----------------------------

    def to_dict(self) -> Dict[str, Any]:
        def case_to_dict(sc: SuiteCase) -> Dict[str, Any]:
            c = sc.case
            return {
                "case_id": c.case_id,
                "runs_repo_name": c.runs_repo_name,
                "label": c.label,
                "repo_key": c.repo.repo_key,
                "repo_url": c.repo.repo_url,
                "repo_path": c.repo.repo_path,
                "branch": c.branch,
                "commit": c.commit,
                "track": c.track,
                "tags": c.tags or {},
                "overrides": {
                    "sonar_project_key": sc.overrides.sonar_project_key,
                    "aikido_git_ref": sc.overrides.aikido_git_ref,
                },
            }

        return {
            "suite_id": self.suite_id,
            "scanners": list(self.scanners or []),
            "analysis": {
                "skip": bool(self.analysis.skip),
                "tolerance": int(self.analysis.tolerance),
                "filter": str(self.analysis.filter),
            },
            "cases": [case_to_dict(sc) for sc in (self.cases or [])],
        }

    @staticmethod
    def from_dict(raw: Dict[str, Any]) -> "SuiteDefinition":
        raw = raw or {}

        analysis_raw = raw.get("analysis") or {}
        analysis = SuiteAnalysisDefaults(
            skip=bool(analysis_raw.get("skip", False)),
            tolerance=int(analysis_raw.get("tolerance", 3)),
            filter=str(analysis_raw.get("filter", "security")),
        )

        scanners = raw.get("scanners") or raw.get("tools") or []
        if isinstance(scanners, str):
            scanners = [t.strip() for t in scanners.split(",") if t.strip()]
        if not isinstance(scanners, list):
            scanners = []

        cases: List[SuiteCase] = []
        for c_raw in (raw.get("cases") or []):
            if not isinstance(c_raw, dict):
                continue

            # Allow both nested overrides and top-level convenience keys.
            ov_raw = c_raw.get("overrides") or {}
            if not isinstance(ov_raw, dict):
                ov_raw = {}

            overrides = SuiteCaseOverrides(
                sonar_project_key=(ov_raw.get("sonar_project_key") or c_raw.get("sonar_project_key")),
                aikido_git_ref=(ov_raw.get("aikido_git_ref") or c_raw.get("aikido_git_ref")),
            )

            repo = RepoSpec(
                repo_key=c_raw.get("repo_key"),
                repo_url=c_raw.get("repo_url"),
                repo_path=c_raw.get("repo_path"),
            )

            case_id = str(c_raw.get("case_id") or "").strip() or "case"
            label = str(c_raw.get("label") or case_id)

            # runs_repo_name is a legacy compatibility knob; default to case_id.
            runs_repo_name = str(c_raw.get("runs_repo_name") or case_id)

            tags = (c_raw.get("tags") or {}) if isinstance(c_raw.get("tags"), dict) else {}
            track = c_raw.get("track") or tags.get("track")

            case = CaseSpec(
                case_id=case_id,
                runs_repo_name=runs_repo_name,
                label=label,
                repo=repo,
                branch=c_raw.get("branch"),
                commit=c_raw.get("commit"),
                track=str(track).strip() if track else None,
                tags=tags,
            )

            cases.append(SuiteCase(case=case, overrides=overrides))

        return SuiteDefinition(
            suite_id=raw.get("suite_id") or None,
            scanners=list(scanners),
            cases=cases,
            analysis=analysis,
        )


# ----------------------------
# YAML IO
# ----------------------------

def load_suite_yaml(path: str | Path) -> SuiteDefinition:
    """Load a suite definition from YAML."""
    import yaml
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"Suite definition not found: {p}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"Suite YAML must be a mapping/object at top level: {p}")
    return SuiteDefinition.from_dict(raw)


def dump_suite_yaml(path: str | Path, suite_def: SuiteDefinition) -> Path:
    """Write a suite definition YAML to the given path."""
    import yaml
    p = Path(path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    data = suite_def.to_dict()
    # Preserve a stable, readable order.
    text = yaml.safe_dump(
        data,
        sort_keys=False,
        default_flow_style=False,
        width=120,
    )
    p.write_text(text, encoding="utf-8")
    return p
