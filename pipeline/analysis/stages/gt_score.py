from __future__ import annotations

"""pipeline.analysis.stages.gt_score

Optional Ground Truth (GT) scoring stage.

Why optional?
------------
Many benchmark targets (e.g., OWASP Juice Shop) will not ship a GT catalog.
For those cases this stage cleanly skips without affecting other analysis stages.

When a GT catalog is present, this stage writes:
  <case_dir>/gt/gt_score.json
  <case_dir>/gt/gt_score.csv

GT catalog discovery order
--------------------------
1) Captured suite artifacts (preferred):
     <case_dir>/gt/gt_catalog.(yaml|yml)
2) Repo-local benchmark folder (best-effort):
     <repo_path>/benchmark/gt_catalog.(yaml|yml)

The stage tries to infer <repo_path> from <case_dir>/case.json when available.

Catalog format
--------------
Accepts either:
- {"items": [ ... ]}
- [ ... ]

Each item should contain at least:
- id
- file
- start_line
- end_line

Optionally:
- track
- set
- branch

Matching
--------
A GT item is considered "matched" if ANY tool produced a normalized finding whose
normalized file path matches and whose line range overlaps (with tolerance).
"""

from collections import Counter
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from pipeline.analysis.framework import AnalysisContext, ArtifactStore, register_stage
from pipeline.analysis.io.write_artifacts import write_csv, write_json
from pipeline.analysis.utils.path_norm import normalize_file_path

from ._shared import build_location_items


def _try_import_yaml():
    try:
        import yaml  # type: ignore

        return yaml, None
    except Exception as e:  # pragma: no cover
        return None, str(e)


def _find_case_dir(ctx: AnalysisContext) -> Optional[Path]:
    out_dir = Path(ctx.out_dir)
    if out_dir.name == "analysis":
        return out_dir.parent
    return None


def _load_case_json(case_dir: Path) -> Dict[str, Any]:
    p = case_dir / "case.json"
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _find_gt_catalog(ctx: AnalysisContext) -> Optional[Path]:
    case_dir = _find_case_dir(ctx)
    if not case_dir:
        return None

    # 1) captured into case_dir/gt/
    gt_dir = case_dir / "gt"
    for name in ("gt_catalog.yaml", "gt_catalog.yml"):
        p = gt_dir / name
        if p.exists() and p.is_file():
            return p

    # 2) repo-local benchmark folder (if we can infer repo_path)
    case_json = _load_case_json(case_dir)
    repo_path = None
    try:
        repo_path = (case_json.get("repo") or {}).get("repo_path")
    except Exception:
        repo_path = None

    if repo_path:
        bench_dir = Path(str(repo_path)) / "benchmark"
        for name in ("gt_catalog.yaml", "gt_catalog.yml"):
            p = bench_dir / name
            if p.exists() and p.is_file():
                return p

    return None


def _parse_gt_items(gt_data: Any) -> List[Dict[str, Any]]:
    if isinstance(gt_data, dict) and isinstance(gt_data.get("items"), list):
        return [it for it in gt_data["items"] if isinstance(it, dict)]
    if isinstance(gt_data, list):
        return [it for it in gt_data if isinstance(it, dict)]
    return []


def _to_int(x: Any) -> Optional[int]:
    try:
        if x is None:
            return None
        return int(x)
    except Exception:
        return None


def _overlaps(
    a_start: Optional[int],
    a_end: Optional[int],
    b_start: Optional[int],
    b_end: Optional[int],
    *,
    tol: int = 0,
) -> bool:
    """Return True if [a_start,a_end] overlaps [b_start,b_end] with tolerance."""
    if a_start is None or b_start is None:
        return False

    a_end = a_end if a_end is not None else a_start
    b_end = b_end if b_end is not None else b_start

    return (a_start <= (b_end + tol)) and (a_end >= (b_start - tol))


def _match_tools_for_gt(
    *,
    gt_file: str,
    gt_start: Optional[int],
    gt_end: Optional[int],
    location_items: Iterable[Dict[str, Any]],
    repo_name: str,
    tol: int,
) -> List[str]:
    gt_fp = normalize_file_path(gt_file, repo_name=repo_name)
    tools: set[str] = set()
    for it in location_items:
        fp = str(it.get("file_path") or "")
        if not fp or not gt_fp:
            continue
        if fp != gt_fp:
            continue

        s = _to_int(it.get("line_number"))
        e = _to_int(it.get("end_line_number"))

        if _overlaps(s, e, gt_start, gt_end, tol=tol):
            t = str(it.get("tool") or "").strip()
            if t:
                tools.add(t)

    return sorted(tools)


@register_stage(
    "gt_score",
    kind="analysis",
    description="Optional GT scoring against gt_catalog.yaml when present.",
)
def stage_gt_score(ctx: AnalysisContext, store: ArtifactStore) -> Dict[str, Any]:
    case_dir = _find_case_dir(ctx)
    if not case_dir:
        # Not running in v2 case layout
        return {"status": "skipped", "reason": "not_case_layout"}

    gt_path = _find_gt_catalog(ctx)
    if gt_path is None:
        # No GT catalog for this case; treat GT scoring as optional.
        store.add_warning("gt_score skipped: gt_catalog not found")
        return {"status": "skipped", "reason": "gt_catalog_not_found"}

    yaml_mod, yaml_err = _try_import_yaml()
    if yaml_mod is None:
        store.add_warning("gt_score skipped: PyYAML not installed")
        return {"status": "skipped", "reason": "pyyaml_not_installed", "error": yaml_err}

    gt_dir = case_dir / "gt"
    gt_dir.mkdir(parents=True, exist_ok=True)

    gt_data = yaml_mod.safe_load(gt_path.read_text(encoding="utf-8"))
    gt_items = _parse_gt_items(gt_data)

    # Use shared normalized findings flattening (already filtered by ctx.mode)
    location_items = build_location_items(ctx, store)

    rows: List[Dict[str, Any]] = []
    by_set_total: Counter[str] = Counter()
    by_set_matched: Counter[str] = Counter()
    by_track_total: Counter[str] = Counter()
    by_track_matched: Counter[str] = Counter()

    matched_count = 0

    for gt in gt_items:
        gt_id = str(gt.get("id") or "")
        gt_file = str(gt.get("file") or "")
        gt_start = _to_int(gt.get("start_line") or gt.get("startLine"))
        gt_end = _to_int(gt.get("end_line") or gt.get("endLine"))
        gt_track = str(gt.get("track") or "").strip() or "unknown"
        gt_set = str(gt.get("set") or "").strip() or "unknown"

        by_set_total[gt_set] += 1
        by_track_total[gt_track] += 1

        tools = _match_tools_for_gt(
            gt_file=gt_file,
            gt_start=gt_start,
            gt_end=gt_end,
            location_items=location_items,
            repo_name=ctx.repo_name,
            tol=int(ctx.tolerance),
        )
        matched = bool(tools)
        if matched:
            matched_count += 1
            by_set_matched[gt_set] += 1
            by_track_matched[gt_track] += 1

        rows.append(
            {
                "gt_id": gt_id,
                "file": normalize_file_path(gt_file, repo_name=ctx.repo_name),
                "start_line": gt_start,
                "end_line": gt_end,
                "track": gt_track,
                "set": gt_set,
                "matched": matched,
                "matched_tools": ",".join(tools),
                "matched_tool_count": len(tools),
            }
        )

    total = len(rows)
    summary: Dict[str, Any] = {
        "status": "ok",
        "gt_catalog_path": str(gt_path),
        "total_gt_items": total,
        "matched_gt_items": matched_count,
        "match_rate": (matched_count / total) if total else 0.0,
        "by_set": {
            s: {"total": int(by_set_total[s]), "matched": int(by_set_matched[s])}
            for s in sorted(by_set_total.keys())
        },
        "by_track": {
            t: {"total": int(by_track_total[t]), "matched": int(by_track_matched[t])}
            for t in sorted(by_track_total.keys())
        },
    }

    out_json = write_json(gt_dir / "gt_score.json", {"summary": summary, "rows": rows})
    out_csv = write_csv(
        gt_dir / "gt_score.csv",
        rows,
        fieldnames=[
            "gt_id",
            "track",
            "set",
            "file",
            "start_line",
            "end_line",
            "matched",
            "matched_tool_count",
            "matched_tools",
        ],
    )

    store.add_artifact("gt_score_json", out_json)
    store.add_artifact("gt_score_csv", out_csv)

    return summary
