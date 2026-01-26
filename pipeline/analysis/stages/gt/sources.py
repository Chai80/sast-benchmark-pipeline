from __future__ import annotations

"""pipeline.analysis.stages.gt.sources

GT source discovery + loading.

This module answers:
  "Where does GT come from for this case?" (markers vs YAML vs none)

It is intentionally isolated from matching/scoring so it can be tested and
extended independently.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from pipeline.analysis.framework import AnalysisContext
from sast_benchmark.gt.markers import extract_gt_markers


def find_case_dir(ctx: AnalysisContext) -> Optional[Path]:
    """Return <case_dir> when running in suite layout; otherwise None."""
    out_dir = Path(ctx.out_dir)
    if out_dir.name == "analysis" and out_dir.parent:
        return out_dir.parent
    return None


def load_case_json(case_dir: Path) -> Dict[str, Any]:
    """Load <case_dir>/case.json if present (best-effort)."""
    p = case_dir / "case.json"
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def case_scoring_track(case_json: Mapping[str, Any]) -> Optional[str]:
    """Infer a case track string from case.json (best-effort)."""
    # Newer suite manifests nest under case.track
    try:
        case_obj = case_json.get("case")
        if isinstance(case_obj, dict) and case_obj.get("track"):
            return str(case_obj.get("track") or "").strip() or None
    except Exception:
        pass

    # Legacy fallbacks
    track = None
    try:
        track = case_json.get("track") or (case_json.get("tags") or {}).get("track")
    except Exception:
        track = None

    return str(track).strip() if track else None


def _try_load_yaml(path: Path) -> Tuple[Optional[Any], Optional[str]]:
    try:
        import yaml  # type: ignore

        return yaml.safe_load(path.read_text(encoding="utf-8")), None
    except Exception as e:
        return None, str(e)


def load_gt_catalog_yaml(
    gt_dir: Path,
) -> Tuple[Optional[Path], List[Dict[str, Any]], Optional[str]]:
    """Load a YAML GT catalog from gt_catalog.yaml or gt_catalog.yml.

    Returns (path, items, error).
    """
    p = gt_dir / "gt_catalog.yaml"
    if not p.exists():
        p = gt_dir / "gt_catalog.yml"
    if not p.exists():
        return None, [], None

    data, err = _try_load_yaml(p)
    if data is None and err:
        return p, [], err

    # Accept either:
    # - a list of items
    # - {items: [...]} wrapper
    items_raw: Any = data
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        items_raw = data.get("items")

    items: List[Dict[str, Any]] = []
    if isinstance(items_raw, list):
        for row in items_raw:
            if isinstance(row, dict):
                items.append(dict(row))

    return p, items, None


def load_gt_markers_json(gt_dir: Path) -> List[Dict[str, Any]]:
    """Load captured marker GT from <case_dir>/gt/gt_markers.json (if present)."""
    p = gt_dir / "gt_markers.json"
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []

    # Accept list directly or {items:[...]}.
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        data = data.get("items")

    items: List[Dict[str, Any]] = []
    if isinstance(data, list):
        for row in data:
            if isinstance(row, dict):
                items.append(dict(row))
    return items


def extract_markers_from_repo(
    case_json: Mapping[str, Any],
) -> Tuple[Optional[Path], List[Dict[str, Any]]]:
    """Extract DURINN_GT markers by scanning the repo path from case.json."""
    repo_path = None
    try:
        repo_path = (case_json.get("repo") or {}).get("repo_path")
    except Exception:
        repo_path = None

    if not repo_path:
        return None, []

    p = Path(str(repo_path))
    if not p.exists() or not p.is_dir():
        return p, []

    items = extract_gt_markers(p)
    return p, items


def choose_gt_source(
    gt_source_mode: str,
    *,
    gt_dir: Path,
    case_json: Mapping[str, Any],
) -> Tuple[
    Optional[str], List[Dict[str, Any]], Optional[Path], Optional[Dict[str, Any]]
]:
    """Choose + load raw GT items for a case.

    Parameters
    ----------
    gt_source_mode:
        One of: "auto", "markers", "yaml".
    gt_dir:
        <case_dir>/gt directory.
    case_json:
        Parsed case.json (best-effort).

    Returns
    -------
    (gt_source_used, raw_items, gt_catalog_path, skip)

    Where:
      - gt_source_used is "markers" or "yaml" when items are found.
      - raw_items is a list of dict rows.
      - gt_catalog_path is set when YAML is used (or attempted).
      - skip is a dict ready to return from the stage when scoring should be skipped.
    """

    gt_source_used: Optional[str] = None
    raw_items: List[Dict[str, Any]] = []
    gt_catalog_path: Optional[Path] = None

    if gt_source_mode == "yaml":
        gt_catalog_path, raw_items, err = load_gt_catalog_yaml(gt_dir)
        if gt_catalog_path is None:
            # required in yaml mode
            return (
                None,
                [],
                None,
                {
                    "status": "skipped",
                    "reason": "no_gt_catalog_yaml",
                    "gt_source_mode": "yaml",
                },
            )
        if err:
            return (
                None,
                [],
                gt_catalog_path,
                {
                    "status": "skipped",
                    "reason": "gt_catalog_yaml_error",
                    "gt_source_mode": "yaml",
                    "gt_catalog_path": str(gt_catalog_path),
                    "error": err,
                },
            )
        if not raw_items:
            return (
                None,
                [],
                gt_catalog_path,
                {
                    "status": "skipped",
                    "reason": "empty_gt_catalog_yaml",
                    "gt_source_mode": "yaml",
                    "gt_catalog_path": str(gt_catalog_path),
                },
            )
        gt_source_used = "yaml"
        return gt_source_used, raw_items, gt_catalog_path, None

    if gt_source_mode not in ("auto", "markers"):
        # Callers validate; keep conservative behavior.
        return (
            None,
            [],
            None,
            {
                "status": "skipped",
                "reason": "no_gt",
                "gt_source_mode": str(gt_source_mode),
            },
        )

    # 1) Captured marker catalog, if present
    raw_items = load_gt_markers_json(gt_dir)
    if raw_items:
        gt_source_used = "markers"

    # 2) Scan repo for DURINN_GT markers (tests rely on this)
    if not raw_items:
        _repo_path, scanned = extract_markers_from_repo(case_json)
        raw_items = scanned
        if raw_items:
            gt_source_used = "markers"

    if gt_source_mode == "markers" and not raw_items:
        return (
            None,
            [],
            None,
            {
                "status": "skipped",
                "reason": "no_gt_markers",
                "gt_source_mode": "markers",
            },
        )

    # 3) YAML fallback (auto only)
    if gt_source_mode == "auto" and not raw_items:
        gt_catalog_path, raw_items, err = load_gt_catalog_yaml(gt_dir)
        if err:
            return (
                None,
                [],
                gt_catalog_path,
                {
                    "status": "skipped",
                    "reason": "gt_catalog_yaml_error",
                    "gt_source_mode": "auto",
                    "gt_catalog_path": str(gt_catalog_path)
                    if gt_catalog_path
                    else None,
                    "error": err,
                },
            )
        if raw_items:
            gt_source_used = "yaml"

    if not raw_items:
        return (
            None,
            [],
            gt_catalog_path,
            {"status": "skipped", "reason": "no_gt", "gt_source_mode": gt_source_mode},
        )

    return gt_source_used, raw_items, gt_catalog_path, None
