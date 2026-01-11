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


def run_suite(
    *,
    repo_name: str,
    tools: Sequence[str],
    runs_dir: Path,
    out_dir: Path,
    tolerance: int = 3,
    mode: str = "security",
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
        Line clustering tolerance used by location clustering.
    mode:
        "security" filters out non-security findings (mainly Sonar CODE_SMELL).
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
            f"No normalized runs found for repo={repo_name!r} under {runs_dir}. "            f"Tried tools={requested_tools}"
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
        mode=mode,
        formats=fmt,
        normalized_paths=normalized_paths,
        config={"requested_tools": requested_tools, "missing_tools": missing_tools},
    )
    store = ArtifactStore()
    if missing_tools:
        store.add_warning(f"Missing tools skipped: {', '.join(missing_tools)}")

    stage_results = []
    stage_results += run_pipeline(ctx, stage_names=PIPELINES["benchmark"], store=store, continue_on_error=True)
    stage_results += run_pipeline(ctx, stage_names=PIPELINES["reporting"], store=store, continue_on_error=True)
    if run_diagnostics:
        stage_results += run_pipeline(ctx, stage_names=PIPELINES["diagnostics"], store=store, continue_on_error=True)

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
        "tools_requested": requested_tools,
        "tools_used": used_tools,
        "tools_missing": missing_tools,
        "stages": stages_summary,
        "artifacts": store.artifact_paths_rel(out_dir),
        "analysis_manifest": str(manifest_path),
        "warnings": list(store.warnings),
        "errors": list(store.errors),
    }
