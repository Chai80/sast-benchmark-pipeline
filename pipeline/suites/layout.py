"""pipeline.suites.layout

Filesystem layout helpers.

This module is a thin wrapper around :mod:`pipeline.suites.bundles` (the suite/case
layout implementation) plus a small set of helper functions used by the CLI and
analysis code.

Why this exists
---------------
Historically, directory naming, run discovery, and "where did this tool write
its output" logic lived in the CLI. That grows quickly into spaghetti.

Phase 1 of the CLI refactor moves:
- suite/case path computation
- "latest run" discovery inside a tool output folder

...into one place.

Notes
-----
- We keep the underlying implementation in pipeline.suites.bundles for backwards
  compatibility (some older patches and docs still refer to "bundles").
- New code should prefer the "suite" terminology exposed here.
"""

from __future__ import annotations

from dataclasses import dataclass

from pathlib import Path
from typing import Any, Dict, Optional, Union

from sast_benchmark.io.layout import (
    discover_latest_run_dir as _discover_latest_run_dir,
    discover_repo_dir as _discover_repo_dir,
)

from pipeline.suites.bundles import (
    BundlePaths,
    anchor_under_repo_root,
    ensure_bundle_dirs,
    get_bundle_paths,
    new_bundle_id,
    safe_name,
    update_suite_artifacts as _update_suite_artifacts,
    write_latest_pointer as _write_latest_pointer,
)


@dataclass(frozen=True)
class SuitePaths:
    """Computed filesystem paths for one case inside one suite.

    This is the canonical 'suite' terminology view used by the pipeline. Internally,
    the legacy implementation lives in :class:`pipeline.suites.bundles.BundlePaths`.
    """

    suite_root: Path
    case_id: str
    suite_id: str

    # Suite-level
    suite_dir: Path
    cases_dir: Path
    suite_readme_path: Path
    suite_json_path: Path
    suite_summary_path: Path
    latest_pointer_path: Path  # runs/suites/LATEST

    # Case-level
    case_dir: Path
    tool_runs_dir: Path
    analysis_dir: Path
    gt_dir: Path
    case_json_path: Path


def _to_suite_paths(bp: BundlePaths) -> SuitePaths:
    return SuitePaths(
        suite_root=bp.bundle_root,
        case_id=bp.target,
        suite_id=bp.bundle_id,
        suite_dir=bp.suite_dir,
        cases_dir=bp.cases_dir,
        suite_readme_path=bp.suite_readme_path,
        suite_json_path=bp.suite_json_path,
        suite_summary_path=bp.suite_summary_path,
        latest_pointer_path=bp.latest_pointer_path,
        case_dir=bp.case_dir,
        tool_runs_dir=bp.tool_runs_dir,
        analysis_dir=bp.analysis_dir,
        gt_dir=bp.gt_dir,
        case_json_path=bp.case_json_path,
    )


def _to_bundle_paths(sp: SuitePaths) -> BundlePaths:
    """Convert :class:`SuitePaths` to legacy :class:`BundlePaths`.

    This keeps the legacy bundles implementation as an internal detail while allowing
    new code to use suite terminology end-to-end.
    """
    return BundlePaths(
        bundle_root=sp.suite_root,
        target=sp.case_id,
        bundle_id=sp.suite_id,
        suite_dir=sp.suite_dir,
        cases_dir=sp.cases_dir,
        suite_readme_path=sp.suite_readme_path,
        suite_json_path=sp.suite_json_path,
        suite_summary_path=sp.suite_summary_path,
        latest_pointer_path=sp.latest_pointer_path,
        case_dir=sp.case_dir,
        tool_runs_dir=sp.tool_runs_dir,
        analysis_dir=sp.analysis_dir,
        gt_dir=sp.gt_dir,
        case_json_path=sp.case_json_path,
    )


def list_suite_dirs(*, suite_root: Union[str, Path] = "runs/suites") -> list[Path]:
    """List suite directories under the suite root.

    Returns an empty list if the suite_root does not exist.
    """
    root = anchor_under_repo_root(suite_root)
    if not root.exists():
        return []
    return sorted([p.resolve() for p in root.iterdir() if p.is_dir()])


def resolve_suite_id(*, suite_id: str, suite_root: Union[str, Path] = "runs/suites") -> str:
    """Resolve a suite id, supporting the special alias ``latest``.

    Rules:
    - If suite_id is not "latest" (case-insensitive), return the trimmed suite_id.
    - If suite_id is "latest" and ``<suite_root>/LATEST`` exists, use its contents.
    - Otherwise, fall back to lexicographically-latest directory name under suite_root.

    This is intentionally conservative: it only resolves to existing suites.
    """
    bid = (suite_id or "").strip()
    if bid.lower() != "latest":
        return bid

    root = anchor_under_repo_root(suite_root)

    # Prefer an explicit pointer file if present.
    latest_file = root / "LATEST"
    if latest_file.exists():
        pointer = latest_file.read_text(encoding="utf-8").strip()
        if pointer:
            suite_dir = (root / safe_name(pointer)).resolve()
            if suite_dir.is_dir():
                return pointer
            raise FileNotFoundError(f"Latest suite pointer points to missing dir: {suite_dir}")

    if not root.exists():
        raise FileNotFoundError(f"No suites directory found: {root}")

    candidates = [p for p in root.iterdir() if p.is_dir()]
    if not candidates:
        raise FileNotFoundError(f"No suite runs found under: {root}")

    # Fall back to lexicographically-latest suite directory name.
    return max(candidates, key=lambda p: p.name).name


def resolve_suite_dir(*, suite_id: str, suite_root: Union[str, Path] = "runs/suites") -> Path:
    """Resolve a suite id to an on-disk suite directory."""
    root = anchor_under_repo_root(suite_root)
    resolved_suite_id = resolve_suite_id(suite_id=suite_id, suite_root=root)
    suite_dir = (root / safe_name(resolved_suite_id)).resolve()
    if not suite_dir.exists() or not suite_dir.is_dir():
        raise FileNotFoundError(f"Suite dir not found: {suite_dir}")
    return suite_dir


def resolve_suite_dir_ref(
    *, suite_dir_ref: Union[str, Path], suite_root: Union[str, Path] = "runs/suites"
) -> Path:
    """Resolve either a suite directory path or a suite id (including ``latest``)."""
    ref = Path(suite_dir_ref)
    if ref.is_dir():
        return ref.resolve()

    anchored = anchor_under_repo_root(ref)
    if anchored.is_dir():
        return anchored.resolve()

    return resolve_suite_dir(suite_id=str(suite_dir_ref), suite_root=suite_root)


def find_case_dir(path: Union[str, Path]) -> Optional[Path]:
    """Walk up from *path* to locate ``.../cases/<case_id>``.

    Returns ``None`` if the path is not inside a v2 suite layout.
    """
    p = Path(path)
    if p.is_file():
        p = p.parent
    p = p.resolve()

    for candidate in [p, *p.parents]:
        if candidate.parent.name == "cases":
            return candidate

    return None


def suite_dir_from_case_dir(case_dir: Path) -> Path:
    """Return the suite dir for a ``.../cases/<case_id>`` directory."""
    case_dir = Path(case_dir).resolve()
    if case_dir.parent.name != "cases":
        raise ValueError(f"Not a case dir (expected .../cases/<case_id>): {case_dir}")
    return case_dir.parent.parent.resolve()


def suite_paths_from_case_dir(case_dir: Path) -> SuitePaths:
    """Build :class:`SuitePaths` from an existing case directory."""
    case_dir = Path(case_dir).resolve()
    suite_dir = suite_dir_from_case_dir(case_dir)
    suite_root = suite_dir.parent
    return get_suite_paths(case_id=case_dir.name, suite_id=suite_dir.name, suite_root=suite_root)


def suite_paths_from_path(path: Union[str, Path]) -> SuitePaths:
    """Build :class:`SuitePaths` from any path inside a case directory."""
    case_dir = find_case_dir(path)
    if case_dir is None:
        raise ValueError(f"Path is not inside a suite case directory: {path}")
    return suite_paths_from_case_dir(case_dir)


def new_suite_id() -> str:
    """Generate a new suite id (sortable UTC timestamp)."""
    return new_bundle_id()


def get_suite_paths(
    *,
    case_id: str,
    suite_id: str,
    suite_root: Union[str, Path] = "runs/suites",
) -> SuitePaths:
    """Compute filesystem paths for one case inside one suite."""
    resolved_suite_id = resolve_suite_id(suite_id=suite_id, suite_root=suite_root)
    bundle = get_bundle_paths(target=case_id, bundle_id=resolved_suite_id, bundle_root=suite_root)
    return _to_suite_paths(bundle)


def ensure_suite_dirs(paths: SuitePaths) -> None:
    """Create the suite/case directory scaffolding."""
    ensure_bundle_dirs(_to_bundle_paths(paths))


def write_latest_suite_pointer(paths: SuitePaths) -> None:
    """Write/overwrite runs/suites/LATEST with the current suite id."""
    _write_latest_pointer(_to_bundle_paths(paths))


def update_suite_artifacts(paths: SuitePaths, case_manifest: Dict[str, Any]) -> None:
    """Update suite-level README / suite.json / summary.csv (best-effort)."""
    _update_suite_artifacts(_to_bundle_paths(paths), case_manifest)


def resolve_case_dir(
    *,
    case_id: str,
    suite_id: str,
    suite_root: Union[str, Path] = "runs/suites",
) -> Path:
    """Resolve the case directory for an existing suite.

    Why this exists
    ---------------
    Different parts of the pipeline historically derived ``case_id`` differently
    (e.g., "juice_shop" vs "juice-shop"). The filesystem layout is the source of
    truth, so this resolver:

    1) resolves the suite id (supports ``latest``)
    2) lists directories under ``runs/suites/<suite_id>/cases/``
    3) attempts an exact match on the requested ``case_id``
    4) if not found, attempts a best-effort '-' <-> '_' normalization
    5) otherwise, errors with a helpful message listing valid case IDs

    This keeps scan output naming unchanged and only improves analysis-time
    discovery and error handling.
    """

    def _canon_case_id(s: str) -> str:
        # Treat '-' and '_' as interchangeable for historical reasons.
        return s.replace("-", "_")

    root = anchor_under_repo_root(suite_root)
    resolved_suite_id = resolve_suite_id(suite_id=str(suite_id), suite_root=root)
    suite_dir = (root / safe_name(resolved_suite_id)).resolve()
    if not suite_dir.exists() or not suite_dir.is_dir():
        raise FileNotFoundError(f"Suite dir not found: {suite_dir}")

    cases_dir = suite_dir / "cases"
    if not cases_dir.exists() or not cases_dir.is_dir():
        raise FileNotFoundError(f"Cases dir not found: {cases_dir}")

    available = sorted([p.name for p in cases_dir.iterdir() if p.is_dir()])
    if not available:
        raise FileNotFoundError(f"No case directories found under: {cases_dir}")

    requested = safe_name(case_id)

    # 1) Exact match.
    if requested in available:
        return (cases_dir / requested).resolve()

    # 2) '-' <-> '_' normalization match.
    req_canon = _canon_case_id(requested)
    canon_matches = [c for c in available if _canon_case_id(c) == req_canon]
    if len(canon_matches) == 1:
        return (cases_dir / canon_matches[0]).resolve()

    # 3) Helpful error.
    hint: str
    if canon_matches:
        hint = (
            f"Ambiguous case id '{case_id}' for suite '{resolved_suite_id}'. "
            "Multiple case directories match after normalizing '-' and '_': "
            + ", ".join(sorted(canon_matches))
        )
    else:
        hint = f"Case id '{case_id}' not found in suite '{resolved_suite_id}'."

    valid = "\n".join(f"  - {c}" for c in available)
    raise FileNotFoundError(
        f"{hint}\n"
        f"Suite dir: {suite_dir}\n"
        f"Cases dir: {cases_dir}\n"
        f"Valid case IDs:\n{valid}"
    )


def discover_repo_dir(output_root: Path, prefer: Optional[str] = None) -> Optional[Path]:
    """Backwards-compatible wrapper for :func:`sast_benchmark.io.layout.discover_repo_dir`."""
    return _discover_repo_dir(output_root, prefer)


def discover_latest_run_dir(repo_dir: Path) -> Optional[Path]:
    """Backwards-compatible wrapper for :func:`sast_benchmark.io.layout.discover_latest_run_dir`."""
    return _discover_latest_run_dir(repo_dir)
