from __future__ import annotations

import json
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence

from .context import AnalysisContext
from .registry import get_stage
from .stage import StageResult
from .store import ArtifactStore


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_pipeline(
    ctx: AnalysisContext,
    *,
    stage_names: Sequence[str],
    store: Optional[ArtifactStore] = None,
    continue_on_error: bool = True,
) -> List[StageResult]:
    """Run an ordered list of registered stages."""
    store = store or ArtifactStore()
    results: List[StageResult] = []

    for name in stage_names:
        started = _now_iso()
        try:
            stage_def = get_stage(name)
            summary = stage_def.func(ctx, store) or {}
            finished = _now_iso()
            results.append(
                StageResult(
                    name=name,
                    ok=True,
                    started_at=started,
                    finished_at=finished,
                    summary=dict(summary),
                    warnings=list(store.warnings),
                    artifacts=store.artifact_paths_rel(ctx.out_dir),
                )
            )
        except Exception as e:
            finished = _now_iso()
            tb = traceback.format_exc(limit=50)
            store.add_error(f"stage:{name}: {e}")
            results.append(
                StageResult(
                    name=name,
                    ok=False,
                    started_at=started,
                    finished_at=finished,
                    summary={},
                    error=f"{e}",
                    warnings=list(store.warnings),
                    artifacts=store.artifact_paths_rel(ctx.out_dir),
                )
            )
            if not continue_on_error:
                break

            # Continue on error, but leave a breadcrumb for debugging.
            err_path = Path(ctx.out_dir) / f"error_{name}.log"
            try:
                err_path.write_text(tb, encoding="utf-8")
                store.add_artifact(f"error_log_{name}", err_path)
            except Exception:
                pass

    return results


def write_analysis_manifest(
    ctx: AnalysisContext,
    *,
    stage_results: Sequence[StageResult],
    store: ArtifactStore,
    path: Optional[Path] = None,
) -> Path:
    """Write analysis_manifest.json summarizing the run."""
    out_dir = Path(ctx.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    p = path or (out_dir / "analysis_manifest.json")

    data = {
        "generated_at": _now_iso(),
        "context": ctx.as_dict(),
        "stages": [
            {
                "name": r.name,
                "ok": r.ok,
                "started_at": r.started_at,
                "finished_at": r.finished_at,
                "summary": r.summary,
                "error": r.error,
            }
            for r in stage_results
        ],
        "artifacts": store.artifact_paths_rel(out_dir),
        "warnings": list(store.warnings),
        "errors": list(store.errors),
    }

    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    store.add_artifact("analysis_manifest", p)
    return p
