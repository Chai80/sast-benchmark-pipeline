"""pipeline.suites.suite_resolver

Resolver boundary for *suite mode*.

Problem this module solves
-------------------------
Historically, the pipeline supported multiple "suite inputs":

* Portable suite plans (Python suite files exporting ``SUITE_DEF``)
* Machine-specific work orders (CSV files, local worktrees roots)

When orchestration code consumes these inputs directly, multiple layers end up
re-deriving:

* case identifiers (case_id)
* scan targets (repo_url / repo_path / branch / commit)
* output locations

That drift is the source of "spaghetti" symptoms like case-id mismatches
(underscore vs hyphen), portability failures (absolute paths), and analysis
breaking when naming heuristics change.

This module introduces a **single, explicit resolution step**:

  Suite inputs  ->  Resolver  ->  runs/suites/<suite_id>/suite.json (manifest)

After resolution, everything downstream (execution, normalization, analysis,
export) should treat the manifest under ``runs/`` as the **source of truth**.

The resolver is intentionally filesystem-first and best-effort:
it does *not* clone repos or perform network calls. It only normalizes inputs,
ensures directories exist, and writes the canonical suite manifest.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from pipeline.suites.bundles import anchor_under_repo_root, safe_name
from pipeline.core import repo_id_from_repo_url, sanitize_sonar_key_fragment
from pipeline.suites.layout import ensure_suite_dirs, get_suite_paths, write_latest_suite_pointer
from pipeline.models import CaseSpec, RepoSpec
from pipeline.suites.suite_definition import SuiteAnalysisDefaults, SuiteCase, SuiteDefinition

from tools.io import write_json


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _derive_runs_repo_name(*, repo_url: Optional[str], repo_path: Optional[str], fallback: str) -> str:
    """Best-effort repo name used by scanners under legacy outputs."""
    if repo_url:
        last = repo_url.rstrip("/").split("/")[-1]
        return last[:-4] if last.endswith(".git") else last
    if repo_path:
        try:
            return Path(repo_path).resolve().name
        except Exception:
            return Path(str(repo_path)).name
    return fallback


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


RepoRegistry = Mapping[str, Mapping[str, str]]


@dataclass(frozen=True)
class SuiteInputProvenance:
    """How the suite plan was produced (for humans + debugging).

    All fields are optional and should be safe to persist (no secrets).
    """

    suite_file: Optional[str] = None
    cases_from_csv: Optional[str] = None
    worktrees_root: Optional[str] = None
    built_interactively: bool = False


@dataclass(frozen=True)
class ResolvedSuiteCase:
    """A resolved case + per-case computed identifiers used by execution."""

    suite_case: SuiteCase
    repo_id: str


@dataclass(frozen=True)
class ResolvedSuiteRun:
    """Result of resolving a SuiteDefinition into a concrete suite run manifest."""

    suite_id: str
    suite_root: Path
    suite_dir: Path

    scanners: Tuple[str, ...]
    analysis: SuiteAnalysisDefaults
    cases: Tuple[ResolvedSuiteCase, ...]

    created_at: str
    provenance: SuiteInputProvenance


# ---------------------------------------------------------------------------
# Core resolution logic
# ---------------------------------------------------------------------------


def resolve_suite_case(
    sc: SuiteCase,
    *,
    repo_registry: Optional[RepoRegistry] = None,
) -> Tuple[SuiteCase, str]:
    """Resolve a single SuiteCase into an executable SuiteCase + repo_id.

    Responsibilities:
    - resolve repo_key -> (repo_url + label) using the provided registry
    - validate that at least one of repo_url/repo_path is present
    - sanitize case_id for filesystem/DB usage
    - compute repo_id (used for Sonar key derivation)

    This intentionally does not perform git operations.
    """

    c = sc.case
    repo_key = c.repo.repo_key
    repo_url = c.repo.repo_url
    repo_path = c.repo.repo_path
    label = c.label

    # Resolve repo_key -> repo_url via a registry (CLI presets can be passed).
    if repo_key and not repo_url and not repo_path:
        if not repo_registry or repo_key not in repo_registry:
            raise SystemExit(
                f"Suite case '{c.case_id}' uses repo_key='{repo_key}' but it isn't known. "
                "Provide repo_url/repo_path or pass a repo registry that contains this key."
            )
        entry = repo_registry[repo_key]
        repo_url = entry.get("repo_url") or None
        label = entry.get("label", label)

    if not repo_url and not repo_path:
        raise SystemExit(
            f"Suite case '{c.case_id}' must specify one of repo_url, repo_path, or a resolvable repo_key."
        )

    # Improve runs_repo_name if omitted.
    derived_runs_name = _derive_runs_repo_name(repo_url=repo_url, repo_path=repo_path, fallback=c.case_id)
    runs_repo_name = c.runs_repo_name
    if not runs_repo_name or runs_repo_name == c.case_id:
        runs_repo_name = derived_runs_name

    # case_id is the canonical folder + ingestion key.
    case_id = safe_name(c.case_id)

    # Compute repo_id (used for Sonar project key derivation).
    if repo_key:
        repo_id = repo_key
    elif repo_url:
        repo_id = repo_id_from_repo_url(repo_url)
    else:
        # In suite mode, repo_id should be unique per case to avoid Sonar key collisions.
        repo_id = sanitize_sonar_key_fragment(case_id)

    resolved = CaseSpec(
        case_id=case_id,
        runs_repo_name=safe_name(runs_repo_name),
        label=label or case_id,
        repo=RepoSpec(repo_key=repo_key, repo_url=repo_url, repo_path=repo_path),
        branch=c.branch,
        commit=c.commit,
        track=c.track,
        tags=c.tags or {},
    )

    return SuiteCase(case=resolved, overrides=sc.overrides), repo_id


def _case_plan_entry(sc: SuiteCase, *, repo_id: str) -> Dict[str, Any]:
    c = sc.case
    return {
        "case_id": c.case_id,
        "label": c.label,
        "runs_repo_name": c.runs_repo_name,
        "repo_id": repo_id,
        "repo": {
            "repo_key": c.repo.repo_key,
            "repo_url": c.repo.repo_url,
            "repo_path": c.repo.repo_path,
        },
        "branch": c.branch,
        "commit": c.commit,
        "track": c.track,
        "tags": dict(c.tags or {}),
        "gt_required": sc.overrides.gt_required,
        "overrides": {
            "sonar_project_key": sc.overrides.sonar_project_key,
            "aikido_git_ref": sc.overrides.aikido_git_ref,
            "gt_required": sc.overrides.gt_required,
        },
    }


def write_suite_manifest(
    *,
    suite_dir: Path,
    suite_id: str,
    suite_def: SuiteDefinition,
    scanners: Sequence[str],
    analysis: SuiteAnalysisDefaults,
    resolved_cases: Sequence[ResolvedSuiteCase],
    provenance: SuiteInputProvenance,
) -> Path:
    """Create or update runs/suites/<suite_id>/suite.json.

    The manifest is designed to be *append-only* in practice:
    - The resolver writes the initial plan under ``plan``.
    - Execution updates per-case status under top-level ``cases``.

    If suite.json already exists, we preserve existing fields and only
    backfill missing ``plan`` information.
    """

    suite_dir = Path(suite_dir)
    suite_dir.mkdir(parents=True, exist_ok=True)

    path = suite_dir / "suite.json"

    existing: Dict[str, Any] = {}
    if path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                existing = raw
        except Exception:
            existing = {}

    created_at = str(existing.get("created_at") or _now_iso())
    updated_at = _now_iso()

    # Preserve the execution summary map if it already exists.
    cases_summary = existing.get("cases")
    if not isinstance(cases_summary, dict):
        cases_summary = {}

    # Backfill plan only if missing.
    plan = existing.get("plan")
    if not isinstance(plan, dict):
        plan = {
            "workload_id": suite_def.suite_id,
            "scanners": list(scanners),
            "analysis": {
                "skip": bool(analysis.skip),
                "tolerance": int(analysis.tolerance),
                "filter": str(analysis.filter),
                "gt_required_default": analysis.gt_required_default,
            },
            "cases": [_case_plan_entry(rc.suite_case, repo_id=rc.repo_id) for rc in resolved_cases],
            "provenance": {
                "suite_file": provenance.suite_file,
                "cases_from_csv": provenance.cases_from_csv,
                "worktrees_root": provenance.worktrees_root,
                "built_interactively": bool(provenance.built_interactively),
            },
        }

    manifest: Dict[str, Any] = {
        # Schema version for suite.json itself (independent from normalized.json schema).
        "schema_version": int(existing.get("schema_version") or 1),
        # Explicitly call this a *run id* (folder name). Keep suite_id for compat.
        "suite_run_id": str(existing.get("suite_run_id") or suite_id),
        "suite_id": str(existing.get("suite_id") or suite_id),
        "created_at": created_at,
        "updated_at": updated_at,
        "plan": plan,
        # Execution summary populated case-by-case during runs.
        "cases": cases_summary,
    }

    write_json(path, manifest)
    return path


def resolve_suite_run(
    *,
    suite_def: SuiteDefinition,
    suite_id: str,
    suite_root: Path,
    scanners: Sequence[str],
    analysis: SuiteAnalysisDefaults,
    provenance: SuiteInputProvenance | None = None,
    repo_registry: Optional[RepoRegistry] = None,
    ensure_dirs: bool = True,
) -> ResolvedSuiteRun:
    """Resolve a suite plan into a canonical suite run (manifest + resolved cases).

    Parameters
    ----------
    suite_def:
        The suite plan (portable input).
    suite_id:
        Suite run identifier (output folder name under runs/suites/).
    suite_root:
        Base directory for suite runs.
    scanners / analysis:
        Resolved execution knobs for this run.
    provenance:
        How the suite plan was produced (suite file, CSV, interactive, etc.).
    repo_registry:
        Optional mapping for resolving repo_key entries.
    ensure_dirs:
        If True, creates the suite/case directory scaffolding before execution.

    Returns
    -------
    ResolvedSuiteRun
        Contains resolved cases + paths and guarantees that suite.json exists.
    """

    prov = provenance or SuiteInputProvenance()

    sid = safe_name(str(suite_id))
    # Match the canonical suite layout anchoring logic used by bundles/layout.
    # If suite_root is relative, anchor it under the repo root.
    root = anchor_under_repo_root(Path(suite_root).expanduser())
    suite_dir = (root / sid).resolve()

    resolved: List[ResolvedSuiteCase] = []
    seen: set[str] = set()

    for sc in (suite_def.cases or []):
        resolved_sc, repo_id = resolve_suite_case(sc, repo_registry=repo_registry)
        cid = resolved_sc.case.case_id
        if cid in seen:
            raise SystemExit(f"Duplicate case_id after resolution: {cid}")
        seen.add(cid)
        resolved.append(ResolvedSuiteCase(suite_case=resolved_sc, repo_id=repo_id))

    if not resolved:
        raise SystemExit("Suite mode requires at least one case.")

    # Optionally pre-create directories. This makes the suite folder browseable
    # immediately (README + cases/) and helps prevent later code from creating
    # subtly different layouts.
    if ensure_dirs:
        for rc in resolved:
            paths = get_suite_paths(case_id=rc.suite_case.case.case_id, suite_id=sid, suite_root=root)
            ensure_suite_dirs(paths)
            write_latest_suite_pointer(paths)

    created_at = _now_iso()
    write_suite_manifest(
        suite_dir=suite_dir,
        suite_id=sid,
        suite_def=suite_def,
        scanners=scanners,
        analysis=analysis,
        resolved_cases=resolved,
        provenance=prov,
    )

    return ResolvedSuiteRun(
        suite_id=sid,
        suite_root=root,
        suite_dir=suite_dir,
        scanners=tuple(scanners),
        analysis=analysis,
        cases=tuple(resolved),
        created_at=created_at,
        provenance=prov,
    )
