"""pipeline.suites.bundles

Filesystem layout helpers for *suite runs*.

Legacy naming
-------------
This module name predates the project's move to "suite" terminology.
It is kept to avoid churn and to preserve backward compatibility.

New code should prefer importing from `pipeline.suites.layout` and using suite_* naming.

Why this exists
---------------
The pipeline can run *many scanners* across *many cases* (e.g., OWASP branch-per-case
micro-suites). Without a predictable output layout, results are hard to review and
hard to ingest later.

This module defines a suite/case directory structure that is:
- Human-friendly (a reviewer can open a suite folder and understand it quickly)
- DB/ETL-friendly (runs are manifest-driven and paths are stable)

Suite layout (v2)
-----------------
A **suite** is one experiment run (timestamped), and a **case** is one scan target
(e.g., one branch/worktree).

  runs/suites/<suite_id>/                       # <-- OPEN THIS
    README.txt                                  # "Start here"
    suite.json                                  # suite index (cases, timestamps, tools)
    summary.csv                                 # one row per case
    cases/
      <case_id>/
        case.json                               # per-case manifest (what ran)
        tool_runs/
          semgrep/<run_id>/...
          snyk/<run_id>/...
          sonar/<run_id>/...
          aikido/<run_id>/...
        analysis/
          triage_queue.csv
          pairwise_agreement.csv
          taxonomy_analysis.csv
          ...
        gt/
          gt_score.json
          gt_score.csv

Notes
-----
- Older runs may still use the previous layout:
    cases/<case>/scans/<tool>/<repo_name>/<run_id>/...
  The analysis discovery logic has been updated to handle both.
- The term "bundle" is kept in function names for backwards compatibility:
  bundle_id == suite_id, target == case_id.

"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from tools.io import write_json


def _append_suite_warning(paths: "BundlePaths", message: str) -> None:
    """Persist a suite-level warning (best-effort).

    This module is intentionally best-effort and should never crash scans.
    However, *silent* failures make it impossible to trust summary artifacts.

    We write a human-readable warning log at:
      <suite_dir>/suite_warnings.log
    """
    try:
        ts = datetime.now(timezone.utc).isoformat()
        p = paths.suite_dir / "suite_warnings.log"
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] {message}\n")
    except Exception:
        # Never raise from diagnostics logging.
        return


from pipeline.core import ROOT_DIR as REPO_ROOT_DIR

_SAFE_NAME = re.compile(r"[^a-zA-Z0-9_.:-]+")


def anchor_under_repo_root(rel: str | Path) -> Path:
    """Anchor a path under the repo root unless it's already absolute."""
    p = Path(rel)
    if p.is_absolute():
        return p
    return (REPO_ROOT_DIR / p).resolve()


def safe_name(value: str) -> str:
    """Sanitize a string so it can be used as a folder segment.

    Security notes:
    - Reject dot-segments that enable traversal ('..', '.')
    - Avoid leading dots ('.env') to reduce hidden-path surprises
    """
    v = (value or "").strip()
    v = _SAFE_NAME.sub("_", v)
    v = re.sub(r"_+", "_", v).strip("_")
    # Block traversal-style segments
    if v in {".", ".."}:
        return "unknown"
    # Avoid hidden segments
    v = v.lstrip(".")
    return v or "unknown"


def new_bundle_id(now: Optional[datetime] = None) -> str:
    """Return a sortable UTC timestamp id like: 20260104T013000Z."""
    dt = now or datetime.now(timezone.utc)
    return dt.strftime("%Y%m%dT%H%M%SZ")


@dataclass(frozen=True)
class BundlePaths:
    """Computed filesystem paths for one case inside one suite."""

    bundle_root: Path
    target: str  # case id (sanitized)
    bundle_id: str  # suite id (sanitized)

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


def get_bundle_paths(
    *,
    target: str,
    bundle_id: str,
    bundle_root: str | Path = "runs/suites",
) -> BundlePaths:
    """Compute filesystem paths for a case run inside a suite."""
    root = anchor_under_repo_root(bundle_root)
    target_seg = safe_name(target)
    bid_seg = safe_name(bundle_id)

    suite_dir = (root / bid_seg).resolve()
    cases_dir = suite_dir / "cases"

    case_dir = (cases_dir / target_seg).resolve()
    tool_runs_dir = case_dir / "tool_runs"
    analysis_dir = case_dir / "analysis"
    gt_dir = case_dir / "gt"
    case_json_path = case_dir / "case.json"

    latest_pointer_path = (root / "LATEST").resolve()
    suite_readme_path = suite_dir / "README.txt"
    suite_json_path = suite_dir / "suite.json"
    suite_summary_path = suite_dir / "summary.csv"

    return BundlePaths(
        bundle_root=root,
        target=target_seg,
        bundle_id=bid_seg,
        suite_dir=suite_dir,
        cases_dir=cases_dir,
        suite_readme_path=suite_readme_path,
        suite_json_path=suite_json_path,
        suite_summary_path=suite_summary_path,
        latest_pointer_path=latest_pointer_path,
        case_dir=case_dir,
        tool_runs_dir=tool_runs_dir,
        analysis_dir=analysis_dir,
        gt_dir=gt_dir,
        case_json_path=case_json_path,
    )


def ensure_bundle_dirs(paths: BundlePaths) -> None:
    """Create the suite/case directory scaffolding."""
    paths.suite_dir.mkdir(parents=True, exist_ok=True)
    paths.cases_dir.mkdir(parents=True, exist_ok=True)

    paths.case_dir.mkdir(parents=True, exist_ok=True)
    paths.tool_runs_dir.mkdir(parents=True, exist_ok=True)
    paths.analysis_dir.mkdir(parents=True, exist_ok=True)
    paths.gt_dir.mkdir(parents=True, exist_ok=True)

    _ensure_suite_readme(paths)
    _ensure_suite_json(paths)


def write_latest_pointer(paths: BundlePaths) -> None:
    """Write/overwrite runs/suites/LATEST with the current suite id."""
    paths.latest_pointer_path.parent.mkdir(parents=True, exist_ok=True)
    paths.latest_pointer_path.write_text(paths.bundle_id + "\n", encoding="utf-8")


def resolve_bundle_dir(
    *,
    target: str,
    bundle_id: str,
    bundle_root: str | Path = "runs/suites",
) -> Path:
    """Resolve a case directory: runs/suites/<suite_id>/cases/<target>/.

    bundle_id may be 'latest' to use runs/suites/LATEST (or a lexicographic fallback).
    """
    root = anchor_under_repo_root(bundle_root)
    target_seg = safe_name(target)

    bid = (bundle_id or "").strip()
    if bid.lower() == "latest":
        latest_file = root / "LATEST"
        if latest_file.exists():
            bid = latest_file.read_text(encoding="utf-8").strip()

        if not bid:
            if not root.exists():
                raise FileNotFoundError(f"No suites directory found: {root}")
            candidates = [p for p in root.iterdir() if p.is_dir()]
            if not candidates:
                raise FileNotFoundError(f"No suite runs found under: {root}")
            bid = max(candidates, key=lambda p: p.name).name

    bid_seg = safe_name(bid)
    case_dir = (root / bid_seg / "cases" / target_seg).resolve()
    if not case_dir.exists():
        raise FileNotFoundError(f"Case dir not found: {case_dir}")
    return case_dir


# -------------------------------------------------------------------
# Suite-level index files (README / suite.json / summary.csv)
# -------------------------------------------------------------------

_README_TEMPLATE = """This is a Durinn *suite run* folder.

Start here:
  1) Open summary.csv (one row per case)
  2) Then open cases/<case>/analysis/triage_queue.csv for review priorities
  3) Or open cases/<case>/analysis/pairwise_agreement.csv to see convergence

Structure:
  cases/<case>/tool_runs/ -> per-tool raw + normalized outputs
  cases/<case>/analysis/  -> Durinn cross-tool metrics
  cases/<case>/gt/        -> GT-based scoring artifacts (if generated)
  cases/<case>/case.json  -> what was run and where outputs were written

NOTE: These repos are intentionally vulnerable. Keep them private if possible.
"""


def update_suite_artifacts(paths: BundlePaths, case_manifest: Dict[str, Any]) -> None:
    """Update suite-level README / suite.json / summary.csv (best-effort)."""
    import traceback

    def warn(msg: str) -> None:
        _append_suite_warning(paths, msg)

    try:
        _ensure_suite_readme(paths)
        _update_suite_json(paths, case_manifest, warn=warn)
        _write_suite_summary(paths, warn=warn)
    except Exception as e:
        # Never fail the scan/analysis run because summary writing had an issue.
        warn(f"update_suite_artifacts failed: {e}\n{traceback.format_exc()}")
        return


def _ensure_suite_readme(paths: BundlePaths) -> None:
    if paths.suite_readme_path.exists():
        return
    paths.suite_readme_path.write_text(_README_TEMPLATE, encoding="utf-8")


def _ensure_suite_json(paths: BundlePaths) -> None:
    if paths.suite_json_path.exists():
        return
    now = datetime.now(timezone.utc).isoformat()
    data = {
        "suite_id": paths.bundle_id,
        "created_at": now,
        "updated_at": now,
        "cases": {},
    }
    write_json(paths.suite_json_path, data)


def _load_json(
    path: Path, *, warn: Optional[Callable[[str], None]] = None
) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            if warn:
                warn(
                    f"JSON at {path} did not parse to an object; got {type(data).__name__}. Ignoring."
                )
            return None
        return data
    except Exception as e:
        if warn:
            warn(f"Failed to parse JSON at {path}: {e}. Ignoring.")
        return None


def _update_suite_json(
    paths: BundlePaths,
    case_manifest: Dict[str, Any],
    *,
    warn: Optional[Callable[[str], None]] = None,
) -> None:
    paths.suite_dir.mkdir(parents=True, exist_ok=True)

    data = _load_json(paths.suite_json_path, warn=warn) if paths.suite_json_path.exists() else None
    if not data:
        now = datetime.now(timezone.utc).isoformat()
        data = {
            "suite_id": paths.bundle_id,
            "created_at": now,
            "updated_at": now,
            "cases": {},
        }

    data["suite_id"] = paths.bundle_id
    data["updated_at"] = datetime.now(timezone.utc).isoformat()

    # Case identifier: prefer the explicit case id (matches cases/<case_id>/).
    # NOTE: Using runs_repo_name here breaks micro-suite branch runs because many
    # cases can share the same repo name.
    case_id = (case_manifest.get("case") or {}).get("id") or paths.case_dir.name

    repo_name = (case_manifest.get("repo") or {}).get("runs_repo_name")

    rel_case_dir = str(paths.case_dir.relative_to(paths.suite_dir))
    rel_manifest = str(paths.case_json_path.relative_to(paths.suite_dir))
    rel_tool_runs = str(paths.tool_runs_dir.relative_to(paths.suite_dir))
    rel_analysis = str(paths.analysis_dir.relative_to(paths.suite_dir))
    rel_gt = str(paths.gt_dir.relative_to(paths.suite_dir))

    tool_runs = case_manifest.get("tool_runs") or case_manifest.get("scans") or {}
    exit_codes = {k: (v or {}).get("exit_code") for k, v in tool_runs.items()}

    data.setdefault("cases", {})
    data["cases"][case_id] = {
        "repo_name": repo_name,
        "case_dir": rel_case_dir,
        "case_json": rel_manifest,
        "tool_runs_dir": rel_tool_runs,
        "analysis_dir": rel_analysis,
        "gt_dir": rel_gt,
        "finished": (case_manifest.get("timestamps") or {}).get("finished"),
        "scanners_requested": case_manifest.get("scanners_requested") or [],
        "exit_codes": exit_codes,
    }

    write_json(paths.suite_json_path, data)


def _write_suite_summary(
    paths: BundlePaths, *, warn: Optional[Callable[[str], None]] = None
) -> None:
    """Write suite_dir/summary.csv with one row per case (best-effort)."""
    rows = []
    if not paths.cases_dir.exists():
        return

    for case_dir in sorted(
        [p for p in paths.cases_dir.iterdir() if p.is_dir()], key=lambda p: p.name
    ):
        # v2 preferred
        mpath = case_dir / "case.json"
        # v1 fallback
        if not mpath.exists():
            mpath = case_dir / "run_manifest.json"
        if not mpath.exists():
            continue

        m = _load_json(mpath, warn=warn)
        if not m:
            continue
        # Prefer the explicit case id so summary rows remain unique in
        # branch-per-case micro-suites.
        case_id = (m.get("case") or {}).get("id") or case_dir.name
        finished = (m.get("timestamps") or {}).get("finished")
        scanners_requested = m.get("scanners_requested") or []

        tool_runs = m.get("tool_runs") or m.get("scans") or {}
        ok = [t for t, v in tool_runs.items() if (v or {}).get("exit_code") == 0]
        failed = [t for t, v in tool_runs.items() if (v or {}).get("exit_code") not in (0, None)]

        analysis_ran = bool(m.get("analysis"))
        rel_case = str(case_dir.relative_to(paths.suite_dir))
        triage_csv = case_dir / "analysis" / "triage_queue.csv"
        rel_triage = str(triage_csv.relative_to(paths.suite_dir)) if triage_csv.exists() else ""

        rows.append(
            {
                "case": case_id,
                "finished": finished or "",
                "requested": ",".join(scanners_requested),
                "ok": ",".join(ok),
                "failed": ",".join(failed),
                "analysis": "yes" if analysis_ran else "no",
                "case_dir": rel_case,
                "triage_queue": rel_triage,
            }
        )

    paths.suite_summary_path.parent.mkdir(parents=True, exist_ok=True)

    with paths.suite_summary_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "case",
                "finished",
                "requested",
                "ok",
                "failed",
                "analysis",
                "case_dir",
                "triage_queue",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)
