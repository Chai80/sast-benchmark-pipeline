from __future__ import annotations

"""sast_benchmark.gt.catalog

Canonical GT catalog materialization.

Problem
-------
Durinn supports multiple GT authoring styles across suites:
- YAML catalogs checked into the repo (benchmark/gt_catalog.yaml)
- in-code marker comments (e.g., DURINN_GT or GT:<ID>_START/_END)

If the pipeline consumes these formats directly everywhere, the architecture
quickly becomes "spaghetti" (many stages each implementing their own GT logic).

Solution
--------
Introduce a single *materialization* step during suite execution:

  repo checkout (any GT authoring style)
        |
        v
  <case_dir>/gt/gt_catalog.yaml   (canonical artifact)

Downstream analysis reads ONLY the canonical artifact in the suite layout.
This keeps dependencies one-directional:
CLI / orchestration -> materialize -> artifacts -> analysis.

This module is intentionally part of the low-level `sast_benchmark` package so
both execution and analysis can share it without importing each other.
"""

import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .markers import extract_gt_markers


def _try_load_yaml(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        import yaml  # type: ignore
    except Exception as e:
        return None, f"pyyaml_missing: {e}"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as e:
        return None, f"yaml_parse_error: {e}"
    if not isinstance(data, dict):
        return None, "yaml_not_a_mapping"
    return data, None


def _dump_yaml(data: Dict[str, Any]) -> str:
    import yaml  # type: ignore

    # sort_keys=False keeps output stable and human-friendly.
    return yaml.safe_dump(data, sort_keys=False)


def materialize_case_gt_catalog(
    repo_root: Path,
    out_gt_dir: Path,
    *,
    warnings: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Ensure a canonical GT catalog exists in out_gt_dir when possible.

    Precedence (deterministic)
    --------------------------
    1) If <repo_root>/benchmark/gt_catalog.yaml exists, copy it verbatim to:
         <out_gt_dir>/gt_catalog.yaml

       (This preserves existing suite behavior and keeps ingest deterministic.)

    2) Otherwise, attempt to extract in-repo marker GT and *compile*:
         <out_gt_dir>/gt_catalog.yaml

    In both cases, if <repo_root>/benchmark/suite_sets.yaml exists, copy it to:
         <out_gt_dir>/suite_sets.yaml

    Returns a small summary dict:
      {
        "wrote": bool,
        "source": "benchmark_yaml" | "markers" | None,
        "item_count": int,
        "gt_catalog_path": str | None
      }

    Best-effort: never raises (errors are appended to warnings, if provided).
    """
    wrote = False
    source: Optional[str] = None
    item_count = 0
    gt_catalog_path: Optional[str] = None

    try:
        repo_root = Path(repo_root)
        out_gt_dir = Path(out_gt_dir)
        out_gt_dir.mkdir(parents=True, exist_ok=True)

        bench = repo_root / "benchmark"
        gt_src = bench / "gt_catalog.yaml"
        suite_sets_src = bench / "suite_sets.yaml"

        # Copy suite_sets.yaml if present (canonical filename only).
        if suite_sets_src.exists() and suite_sets_src.is_file():
            shutil.copy2(suite_sets_src, out_gt_dir / "suite_sets.yaml")

        # 1) Prefer benchmark YAML if present (canonical filename only).
        if gt_src.exists() and gt_src.is_file():
            shutil.copy2(gt_src, out_gt_dir / "gt_catalog.yaml")
            wrote = True
            source = "benchmark_yaml"
            gt_catalog_path = str(out_gt_dir / "gt_catalog.yaml")

            # Best-effort: count items for summary; do not mutate file.
            data, err = _try_load_yaml(gt_src)
            if isinstance(data, dict):
                items = data.get("items")
                if isinstance(items, list):
                    item_count = sum(1 for x in items if isinstance(x, dict))
            elif err and warnings is not None:
                warnings.append(f"gt_catalog_yaml_read_failed: {err}")

            return {
                "wrote": wrote,
                "source": source,
                "item_count": item_count,
                "gt_catalog_path": gt_catalog_path,
            }

        # 2) Fallback: compile from in-repo markers.
        markers = extract_gt_markers(repo_root)
        if not markers:
            return {"wrote": False, "source": None, "item_count": 0, "gt_catalog_path": None}

        # Canonical, minimal schema. Extra per-item keys are preserved.
        doc: Dict[str, Any] = {
            "version": 1,
            "note": "Generated from in-repo GT markers (DURINN_GT and/or GT:<ID>_START/_END).",
            "items": markers,
        }

        rendered = _dump_yaml(doc)
        out_path = out_gt_dir / "gt_catalog.yaml"
        out_path.write_text(rendered, encoding="utf-8")

        # Optional: write a JSON twin for diff/debug tooling (not used by analysis today).
        try:
            (out_gt_dir / "gt_catalog.json").write_text(json.dumps(doc, indent=2, sort_keys=False), encoding="utf-8")
        except Exception:
            pass

        wrote = True
        source = "markers"
        gt_catalog_path = str(out_path)
        item_count = len(markers)

        return {
            "wrote": wrote,
            "source": source,
            "item_count": item_count,
            "gt_catalog_path": gt_catalog_path,
        }

    except Exception as e:
        if warnings is not None:
            warnings.append(f"gt_catalog_materialize_failed: {e}")
        return {"wrote": False, "source": None, "item_count": 0, "gt_catalog_path": None}
