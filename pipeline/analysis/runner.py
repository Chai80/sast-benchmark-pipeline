from __future__ import annotations

"""pipeline.analysis.runner

Programmatic runner for modular analysis pipelines.

This is the stable API used by:
- :mod:`pipeline.analysis.analyze_suite` (legacy CLI entrypoint)
- :mod:`pipeline.orchestrator` (suite-mode auto-analysis)

It is intentionally conservative:
- additive outputs only (analysis_manifest.json + analysis artifacts)
- no changes to scan execution or normalized schemas

"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pipeline.analysis.framework import AnalysisContext, ArtifactStore
from pipeline.analysis.framework.pipelines import PIPELINES
from pipeline.analysis.framework.runner import run_pipeline, write_analysis_manifest
from pipeline.analysis.io.discovery import find_latest_normalized_json
from pipeline.analysis.io.organize_outputs import organize_analysis_outputs


def _suite_case_dir_from_out_dir(out_dir: Path) -> Optional[Path]:
    """Return the <case_dir> if out_dir matches the v2 suite layout.

    Expected:
      runs/suites/<suite_id>/cases/<case_id>/analysis/
    """
    try:
        out_dir = Path(out_dir)
        if out_dir.name != "analysis":
            return None
        case_dir = out_dir.parent
        if case_dir.parent.name != "cases":
            return None
        return case_dir
    except Exception:
        return None


def _load_gt_policy_from_suite_manifest(case_dir: Path) -> Dict[str, Any]:
    """Best-effort load GT policy knobs from runs/suites/<suite_id>/suite.json.

    Returns a dict that may include:
      - gt_required_effective: Optional[bool]
      - gt_required_source: str (case|default|none)
      - gt_required_default: Optional[bool]
      - case_repo_path: Optional[str]
    """
    out: Dict[str, Any] = {
        "gt_required_effective": None,
        "gt_required_source": "none",
        "gt_required_default": None,
        "case_repo_path": None,
    }
    try:
        suite_dir = case_dir.parent.parent if case_dir.parent.name == "cases" else None
        if not suite_dir:
            return out
        suite_json = suite_dir / "suite.json"
        if not suite_json.exists():
            return out

        raw = json.loads(suite_json.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return out

        plan = raw.get("plan") or {}
        if not isinstance(plan, dict):
            return out

        analysis = plan.get("analysis") or {}
        if isinstance(analysis, dict):
            out["gt_required_default"] = analysis.get("gt_required_default")

        cases = plan.get("cases") or []
        if not isinstance(cases, list):
            return out

        cid = case_dir.name
        for entry in cases:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("case_id") or "") != cid:
                continue

            # Prefer the explicit per-case field if present.
            gt_req = entry.get("gt_required")
            if gt_req is None:
                ov = entry.get("overrides") or {}
                if isinstance(ov, dict):
                    gt_req = ov.get("gt_required")

            repo = entry.get("repo") or {}
            if isinstance(repo, dict):
                out["case_repo_path"] = repo.get("repo_path")

            if gt_req is not None:
                out["gt_required_effective"] = bool(gt_req)
                out["gt_required_source"] = "case"
                return out

            # Fall back to suite default if configured.
            if out.get("gt_required_default") is not None:
                out["gt_required_effective"] = bool(out.get("gt_required_default"))
                out["gt_required_source"] = "default"
            return out

        # Case not found in plan; fall back to suite default if present.
        if out.get("gt_required_default") is not None:
            out["gt_required_effective"] = bool(out.get("gt_required_default"))
            out["gt_required_source"] = "default"
        return out

    except Exception:
        return out


def _count_yaml_gt_items(path: Path) -> Optional[int]:
    """Best-effort parse a gt_catalog.yaml and return len(items) if possible."""
    try:
        import yaml  # type: ignore
    except Exception:
        return None
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if isinstance(data, dict):
            items = data.get("items")
            if isinstance(items, list):
                return len(items)
    except Exception:
        return None
    return None


def _enforce_gt_required(
    *,
    case_dir: Path,
    stage_results: List[Any],
    store: ArtifactStore,
    gt_required: bool,
) -> None:
    """Enforce suite-declared GT requirements (Policy B).

    This is intentionally *file-based* and local-only:
    - We only look at artifacts under <case_dir>/gt/
    - We do NOT clone repos or prompt the user.
    """
    if not gt_required:
        return

    gt_dir = Path(case_dir) / "gt"
    yaml_path = None
    for name in ("gt_catalog.yaml", "gt_catalog.yml"):
        p = gt_dir / name
        if p.exists():
            yaml_path = p
            break

    def _mark_gt_stage_failed(reason: str, message: str) -> None:
        store.add_error(message)
        for r in stage_results:
            try:
                if getattr(r, "name", None) != "gt_score":
                    continue
                r.ok = False
                r.error = message
                s = dict(getattr(r, "summary", {}) or {})
                s.setdefault("status", "error")
                s["reason"] = reason
                s["gt_required"] = True
                r.summary = s
            except Exception:
                continue

    if yaml_path is None:
        _mark_gt_stage_failed(
            "missing_gt_catalog_yaml_required",
            "GT is required for this case but no gt_catalog.yaml/.yml exists under <case_dir>/gt",
        )
        return

    n_items = _count_yaml_gt_items(yaml_path)
    if n_items == 0:
        _mark_gt_stage_failed(
            "empty_gt_catalog_required",
            "GT is required for this case but gt_catalog.yaml contains zero items",
        )
        return


def run_suite(
    *,
    repo_name: str,
    tools: Sequence[str],
    runs_dir: Path,
    out_dir: Path,
    tolerance: int = 3,
    gt_tolerance: int = 0,
    gt_source: str = "auto",
    mode: str = "security",
    exclude_prefixes: Sequence[str] = (),
    include_harness: bool = False,
    formats: Sequence[str] = ("json", "csv"),
    run_diagnostics: bool = False,
) -> Dict[str, Any]:
    """Run the analysis suite for a single repo/case.

    Parameters
    ----------
    repo_name:
        The repo name (legacy) or case runs_repo_name (suite mode).
    tools:
        Tools to include.
    runs_dir:
        Base runs dir. In suite mode this is usually <case_dir>/tool_runs.
    out_dir:
        Output dir. In suite mode this is usually <case_dir>/analysis.
    tolerance:
        Line clustering tolerance used by location clustering + triage UX.
    gt_tolerance:
        Line overlap tolerance used ONLY for GT scoring (gt_score stage).
    mode:
        "security" filters out non-security findings (mainly Sonar CODE_SMELL).
    exclude_prefixes:
        Repeatable repo-relative prefixes to exclude from analysis scope.
    include_harness:
        If True, do not apply suite-layout default harness exclusion.
    formats:
        Output formats to write. Defaults to json + csv.
    run_diagnostics:
        If true, also run the diagnostics pipeline.

    Returns
    -------
    A JSON-serializable summary dict.
    """
    runs_dir = Path(runs_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Suite GT policy (Policy B): best-effort load per-case requirements from suite.json.
    case_dir = _suite_case_dir_from_out_dir(out_dir)
    gt_policy = _load_gt_policy_from_suite_manifest(case_dir) if case_dir else {}

    # Ensure builtin stages are registered.
    # Import side effects: stage registration decorators populate the registry.
    import pipeline.analysis.stages  # noqa: F401
    import pipeline.analysis.exports  # noqa: F401

    requested_tools = [str(t) for t in tools]
    used_tools: List[str] = []
    missing_tools: List[str] = []

    normalized_paths: Dict[str, Path] = {}
    for tool in requested_tools:
        try:
            p = find_latest_normalized_json(runs_dir=runs_dir, tool=tool, repo_name=repo_name)
            normalized_paths[tool] = p
            used_tools.append(tool)
        except FileNotFoundError:
            missing_tools.append(tool)

    if not used_tools:
        raise FileNotFoundError(
            f"No normalized runs found for repo={repo_name!r} under {runs_dir}. "
            f"Tried tools={requested_tools}"
        )

    fmt = tuple([f.strip().lower() for f in formats if str(f).strip()])
    if not fmt:
        fmt = ("json", "csv")

    ctx = AnalysisContext.build(
        repo_name=repo_name,
        tools=used_tools,
        runs_dir=runs_dir,
        out_dir=out_dir,
        tolerance=tolerance,
        gt_tolerance=gt_tolerance,
        mode=mode,
        exclude_prefixes=exclude_prefixes,
        include_harness=include_harness,
        formats=fmt,
        normalized_paths=normalized_paths,
        config={
            "requested_tools": requested_tools,
            "missing_tools": missing_tools,
            "gt_tolerance": int(gt_tolerance),
            "gt_source": str(gt_source),
            "gt_required": gt_policy.get("gt_required_effective"),
            "gt_required_source": gt_policy.get("gt_required_source"),
            "gt_required_default": gt_policy.get("gt_required_default"),
            "gt_required_repo_path": gt_policy.get("case_repo_path"),
        },
    )
    store = ArtifactStore()
    if missing_tools:
        store.add_warning(f"Missing tools skipped: {', '.join(missing_tools)}")

    stage_results = []
    stage_results += run_pipeline(
        ctx, stage_names=PIPELINES["benchmark"], store=store, continue_on_error=True
    )
    stage_results += run_pipeline(
        ctx, stage_names=PIPELINES["reporting"], store=store, continue_on_error=True
    )
    if run_diagnostics:
        stage_results += run_pipeline(
            ctx,
            stage_names=PIPELINES["diagnostics"],
            store=store,
            continue_on_error=True,
        )

    # Enforce suite-declared GT requirements (Policy B).
    # Local-only: we only enforce when the suite manifest recorded a repo_path.
    try:
        gt_req = (
            bool((ctx.config or {}).get("gt_required"))
            if (ctx.config or {}).get("gt_required") is not None
            else False
        )
        repo_path = (ctx.config or {}).get("gt_required_repo_path")
        if gt_req and repo_path and case_dir:
            _enforce_gt_required(
                case_dir=case_dir,
                stage_results=stage_results,
                store=store,
                gt_required=True,
            )
        elif gt_req and not repo_path:
            store.add_warning(
                "gt_required was set, but suite.json did not record a repo_path for this case; skipping enforcement (local-only policy)"
            )
    except Exception:
        pass

    # Plan A: reorganize output files for human UX.
    #
    # We intentionally do this *after* stages run (so they can keep writing to
    # ctx.out_dir) but *before* the manifest is written, so manifest artifact
    # paths reflect the reorganized layout.
    organize_analysis_outputs(out_dir, store=store)

    # benchmark_pack.json embeds an "artifacts" index. Because we reorganize
    # files after the reporting stages run, rewrite the pack with the updated
    # artifact paths so the pack stays internally consistent.
    pack_path = Path(out_dir) / "benchmark_pack.json"
    if pack_path.exists():
        try:
            parsed = json.loads(pack_path.read_text(encoding="utf-8"))
            if isinstance(parsed, dict):
                parsed["artifacts"] = store.artifact_paths_rel(Path(out_dir))
                pack_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
        except Exception:
            # Non-fatal: the pack remains usable even if the artifacts index is stale.
            pass

    manifest_path = write_analysis_manifest(ctx, stage_results=stage_results, store=store)

    # Compact stage status for the returned summary.
    stages_summary = [
        {
            "name": r.name,
            "ok": r.ok,
            "summary": r.summary,
            "error": r.error,
        }
        for r in stage_results
    ]

    return {
        "repo_name": repo_name,
        "suite_id": ctx.suite_id,
        "case_id": ctx.case_id,
        "runs_dir": str(runs_dir),
        "out_dir": str(out_dir),
        "mode": ctx.mode,
        "tolerance": ctx.tolerance,
        "gt_tolerance": int((ctx.config or {}).get("gt_tolerance") or 0),
        "gt_source": str((ctx.config or {}).get("gt_source") or "auto"),
        "tools_requested": requested_tools,
        "tools_used": used_tools,
        "tools_missing": missing_tools,
        "stages": stages_summary,
        "artifacts": store.artifact_paths_rel(out_dir),
        "analysis_manifest": str(manifest_path),
        "warnings": list(store.warnings),
        "errors": list(store.errors),
    }
