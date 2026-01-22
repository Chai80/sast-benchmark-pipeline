from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_json

from .common.store_keys import StoreKeys


def _find_case_dir(ctx: AnalysisContext) -> Optional[Path]:
    """Best-effort locate the case directory in suite mode.

    In suite mode, ctx.out_dir is:
      <suite_dir>/cases/<case_id>/analysis
    """
    out_dir = Path(ctx.out_dir)
    if out_dir.name == "analysis":
        return out_dir.parent
    return None


def _load_case_json(case_dir: Path) -> Optional[Dict[str, Any]]:
    p = case_dir / "case.json"
    if not p.exists() or not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


@register_stage(
    "diagnostics_case_context",
    kind="diagnostic",
    description="Validate scanned git branch/commit against case expectations (suite mode).",
)
def stage_diagnostics_case_context(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    case_dir = _find_case_dir(ctx)
    if not case_dir:
        # Not running in suite mode; nothing to do.
        return {"status": "skipped", "reason": "no_case_dir"}

    case_json = _load_case_json(case_dir)
    if not case_json:
        store.add_warning("diagnostics_case_context: case.json missing or unreadable")
        return {"status": "skipped", "reason": "missing_case_json"}

    expected_branch = (case_json.get("case") or {}).get("expected_branch") or (case_json.get("case") or {}).get("branch")
    expected_commit = (case_json.get("case") or {}).get("expected_commit") or (case_json.get("case") or {}).get("commit")
    actual_branch = (case_json.get("repo") or {}).get("git_branch")
    actual_commit = (case_json.get("repo") or {}).get("git_commit")

    mismatches: Dict[str, Any] = {}
    if expected_branch:
        if not actual_branch:
            mismatches["branch"] = {"expected": expected_branch, "actual": None}
        elif str(expected_branch) != str(actual_branch):
            mismatches["branch"] = {"expected": expected_branch, "actual": actual_branch}

    if expected_commit:
        if not actual_commit:
            mismatches["commit"] = {"expected": expected_commit, "actual": None}
        elif str(expected_commit) != str(actual_commit):
            mismatches["commit"] = {"expected": expected_commit, "actual": actual_commit}

    report = {
        "status": "ok" if not mismatches else "mismatch",
        "expected": {"branch": expected_branch, "commit": expected_commit},
        "actual": {"branch": actual_branch, "commit": actual_commit},
        "mismatches": mismatches,
        "case_dir": str(case_dir),
    }

    out_path = Path(ctx.out_dir) / "diagnostics_case_context.json"
    write_json(out_path, report)
    store.add_artifact("diagnostics_case_context", out_path)
    store.put(StoreKeys.DIAGNOSTICS_CASE_CONTEXT, report)

    if mismatches:
        store.add_warning(
            "diagnostics_case_context: expected vs actual git context mismatch: "
            + ", ".join(sorted(mismatches.keys()))
        )

    return {"mismatches": len(mismatches)}
