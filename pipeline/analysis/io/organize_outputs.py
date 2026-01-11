from __future__ import annotations

"""pipeline.analysis.io.organize_outputs

Plan A output cleanup (minimal engineering).

The analysis suite currently writes a handful of "final" JSON artifacts as well
as several intermediate/debug tables (often duplicated in packs) and optional
CSVs. For human UX and to prevent consumers from accidentally depending on
intermediate artifacts, we reorganize the analysis directory after the suite
runs.

Rules
-----
- Keep final, consumer-facing JSON files in the analysis root.
- Move intermediate/debug JSON + logs into "_checkpoints/".
- Move CSV outputs into "_tables/".

This function is intentionally conservative:
- It only moves top-level files (non-recursive).
- It is idempotent.
- It optionally updates the ArtifactStore so analysis_manifest.json stays
  accurate.

"""

import os
from pathlib import Path
from typing import Dict, Iterable, Optional, Set

from pipeline.analysis.framework.store import ArtifactStore


DEFAULT_KEEP_ROOT: Set[str] = {
    # Always keep the manifest and the two ingestion packs in the root.
    "analysis_manifest.json",
    "benchmark_pack.json",
    "hotspot_drilldown_pack.json",
    # Optional convenience artifact (human-friendly, small).
    "triage_queue.json",
}


def _safe_move(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)

    # If dst exists, overwrite. This keeps reruns predictable.
    # Use os.replace for atomic-ish behavior on a single filesystem.
    os.replace(str(src), str(dst))


def organize_analysis_outputs(
    out_dir: Path,
    *,
    store: Optional[ArtifactStore] = None,
    keep_root: Optional[Iterable[str]] = None,
    checkpoints_dirname: str = "_checkpoints",
    tables_dirname: str = "_tables",
) -> Dict[str, object]:
    """Reorganize analysis outputs for human UX.

    Parameters
    ----------
    out_dir:
        The analysis output directory.
    store:
        Optional ArtifactStore. If provided, artifact paths are updated when
        files are moved.
    keep_root:
        Iterable of filenames to keep in the analysis root.
    checkpoints_dirname:
        Subdir name under out_dir to store intermediate/debug artifacts.
    tables_dirname:
        Subdir name under out_dir to store CSV exports.

    Returns
    -------
    Summary dict (JSON-serializable).
    """
    out_dir = Path(out_dir)
    keep: Set[str] = set(keep_root) if keep_root is not None else set(DEFAULT_KEEP_ROOT)

    checkpoints_dir = out_dir / checkpoints_dirname
    tables_dir = out_dir / tables_dirname

    moved: Dict[str, str] = {}
    moved_tables = 0
    moved_checkpoints = 0

    # Build a reverse index for store updates (old_abs -> new_abs)
    path_updates: Dict[Path, Path] = {}

    if not out_dir.exists():
        return {
            "out_dir": str(out_dir),
            "moved": moved,
            "moved_tables": 0,
            "moved_checkpoints": 0,
        }

    for p in sorted(out_dir.iterdir()):
        # Only handle top-level files.
        if not p.is_file():
            continue

        name = p.name
        if name in keep:
            continue

        # CSV exports -> _tables/
        if name.lower().endswith(".csv"):
            dst = tables_dir / name
            _safe_move(p, dst)
            moved[name] = f"{tables_dirname}/{name}"
            moved_tables += 1
            path_updates[p.resolve()] = dst.resolve()
            continue

        # Everything else (json, log, etc.) -> _checkpoints/
        dst = checkpoints_dir / name
        _safe_move(p, dst)
        moved[name] = f"{checkpoints_dirname}/{name}"
        moved_checkpoints += 1
        path_updates[p.resolve()] = dst.resolve()

    # Update store paths so the manifest stays accurate.
    if store is not None and path_updates:
        for k, v in list(store.artifacts.items()):
            try:
                abs_old = Path(v).resolve()
            except Exception:
                abs_old = Path(v)
            if abs_old in path_updates:
                store.artifacts[k] = path_updates[abs_old]

    return {
        "out_dir": str(out_dir),
        "checkpoints_dir": str(checkpoints_dir),
        "tables_dir": str(tables_dir),
        "moved": moved,
        "moved_tables": moved_tables,
        "moved_checkpoints": moved_checkpoints,
    }
