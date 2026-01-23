from __future__ import annotations

import json
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set

from .context import AnalysisContext
from .registry import get_stage
from .stage import StageResult
from .store import ArtifactStore

from sast_benchmark.io.fs import write_json_atomic


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_pipeline(
    ctx: AnalysisContext,
    *,
    stage_names: Sequence[str],
    store: Optional[ArtifactStore] = None,
    continue_on_error: bool = True,
    strict_deps: bool = False,
) -> List[StageResult]:
    """Run an ordered list of registered stages."""
    store = store or ArtifactStore()
    results: List[StageResult] = []

    stage_defs = [get_stage(n) for n in stage_names]

    def _produces_later(i: int) -> Set[str]:
        out: Set[str] = set()
        for sd in stage_defs[i + 1 :]:
            out.update(sd.produces or ())
        return out

    # Pre-flight: detect obvious ordering mismatches where a stage claims it
    # requires keys that are only produced by later stages.
    available: Set[str] = set(store.data.keys())
    for i, sd in enumerate(stage_defs):
        if not sd.requires:
            available.update(sd.produces or ())
            continue
        missing = [k for k in sd.requires if k not in available]
        if missing:
            later = _produces_later(i)
            wrong_order = [k for k in missing if k in later]
            if wrong_order:
                msg = (
                    f"deps: stage '{sd.name}' requires keys produced later in the pipeline: {wrong_order}. "
                    "Consider reordering stages or adjusting requires/produces."
                )
                if strict_deps:
                    # Fail fast for deterministic debugging.
                    raise RuntimeError(msg)
                store.add_warning(msg)

        available.update(sd.produces or ())

    for stage_def in stage_defs:
        name = stage_def.name
        started = _now_iso()
        try:
            # Dependency check (store keys).
            if stage_def.requires:
                missing_now = [k for k in stage_def.requires if k not in store.data]
                if missing_now:
                    msg = f"deps: stage '{name}' missing required store keys: {missing_now}"
                    if strict_deps:
                        raise KeyError(msg)
                    store.add_warning(msg)

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

    write_json_atomic(p, data, indent=2, sort_keys=True, ensure_ascii=False)
    store.add_artifact("analysis_manifest", p)
    return p
