"""pipeline.bundles

Filesystem layout helpers for *suite runs* (human-first output structure).

Historically this project used the term **bundle** for "one directory that contains
everything for a run". The new structure makes it easier to run *multi-case suites*
(e.g., scanning many Git branches) while keeping outputs easy to browse:

  runs/suites/<suite_id>/                       # <-- OPEN THIS
    README.txt                                  # "Start here"
    suite_manifest.json                         # suite index (cases, timestamps, tools)
    summary.csv                                 # one row per case
    cases/
      <case_name>/
        scans/
          semgrep/<repo_name>/<run_id>/...
          snyk/<repo_name>/<run_id>/...
          sonar/<repo_name>/<run_id>/...
          aikido/<repo_name>/<run_id>/...
        analysis/
          triage_queue.csv
          pairwise_agreement.csv
          taxonomy_analysis.csv
          ...
        run_manifest.json                        # per-case run manifest

Important: the scanner + analysis code already assume the internal scans contract:

  <runs_dir>/<tool>/<repo_name>/<run_id>/<repo_name>.normalized.json

So inside each case folder we keep:

  cases/<case>/scans/<tool>/<repo_name>/<run_id>/...

This module keeps the old names (BundlePaths, get_bundle_paths, etc.) so existing
code and scripts don't break, but "bundle_id" is effectively your **suite_id** and
"target" is your **case name**.

"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from pipeline.core import ROOT_DIR as REPO_ROOT_DIR

_SAFE_NAME = re.compile(r"[^a-zA-Z0-9_.:-]+")


def anchor_under_repo_root(rel: str | Path) -> Path:
    """Anchor a path under the repo root unless it's already absolute."""
    p = Path(rel)
    if p.is_absolute():
        return p
    return (REPO_ROOT_DIR / p).resolve()


def safe_name(value: str) -> str:
    """Sanitize a string so it can be used as a folder segment."""
    v = (value or "").strip()
    v = _SAFE_NAME.sub("_", v)
    v = re.sub(r"_+", "_", v).strip("_")
    return v or "unknown"


def new_bundle_id(now: Optional[datetime] = None) -> str:
    """Return a sortable UTC timestamp id like: 20260104T013000Z."""
    dt = now or datetime.now(timezone.utc)
    return dt.strftime("%Y%m%dT%H%M%SZ")


@dataclass(frozen=True)
class BundlePaths:
    # NOTE: name kept for compatibility; this represents one *case* inside a *suite run*.
    bundle_root: Path
    target: str            # case name (sanitized)
    bundle_id: str         # suite id (sanitized)

    # Suite-level
    suite_dir: Path
    cases_dir: Path
    suite_readme_path: Path
    suite_manifest_path: Path
    suite_summary_path: Path
    latest_pointer_path: Path  # runs/suites/LATEST

    # Case-level (this is what used to be called the "bundle dir")
    bundle_dir: Path       # case_dir = runs/suites/<suite_id>/cases/<case>/
    scans_dir: Path
    analysis_dir: Path
    manifest_path: Path    # cases/<case>/run_manifest.json


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
    scans_dir = case_dir / "scans"
    analysis_dir = case_dir / "analysis"
    manifest_path = case_dir / "run_manifest.json"

    latest_pointer_path = (root / "LATEST").resolve()
    suite_readme_path = suite_dir / "README.txt"
    suite_manifest_path = suite_dir / "suite_manifest.json"
    suite_summary_path = suite_dir / "summary.csv"

    return BundlePaths(
        bundle_root=root,
        target=target_seg,
        bundle_id=bid_seg,
        suite_dir=suite_dir,
        cases_dir=cases_dir,
        suite_readme_path=suite_readme_path,
        suite_manifest_path=suite_manifest_path,
        suite_summary_path=suite_summary_path,
        latest_pointer_path=latest_pointer_path,
        bundle_dir=case_dir,
        scans_dir=scans_dir,
        analysis_dir=analysis_dir,
        manifest_path=manifest_path,
    )


def ensure_bundle_dirs(paths: BundlePaths) -> None:
    """Create the suite/case directory scaffolding."""
    paths.suite_dir.mkdir(parents=True, exist_ok=True)
    paths.cases_dir.mkdir(parents=True, exist_ok=True)

    paths.bundle_dir.mkdir(parents=True, exist_ok=True)
    paths.scans_dir.mkdir(parents=True, exist_ok=True)
    paths.analysis_dir.mkdir(parents=True, exist_ok=True)

    _ensure_suite_readme(paths)
    _ensure_suite_manifest(paths)


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
# Suite-level index files (README / suite_manifest / summary.csv)
# -------------------------------------------------------------------

_README_TEMPLATE = """This is a Durinn *suite run* folder.

Start here:
  1) Open summary.csv (one row per case)
  2) Then open cases/<case>/analysis/triage_queue.csv for review priorities
  3) Or open cases/<case>/analysis/pairwise_agreement.csv to see convergence

Structure:
  cases/<case>/scans/    -> per-tool raw + normalized outputs
  cases/<case>/analysis/ -> Durinn cross-tool metrics
  cases/<case>/run_manifest.json -> what was run and where outputs were written

NOTE: These repos are intentionally vulnerable. Keep them private if possible.
"""


def update_suite_artifacts(paths: BundlePaths, case_manifest: Dict[str, Any]) -> None:
    """Update suite-level README / suite_manifest.json / summary.csv (best-effort)."""
    try:
        _ensure_suite_readme(paths)
        _update_suite_manifest(paths, case_manifest)
        _write_suite_summary(paths)
    except Exception:
        # Never fail the scan/analysis run because summary writing had an issue.
        return


def _ensure_suite_readme(paths: BundlePaths) -> None:
    if paths.suite_readme_path.exists():
        return
    paths.suite_readme_path.write_text(_README_TEMPLATE, encoding="utf-8")


def _ensure_suite_manifest(paths: BundlePaths) -> None:
    if paths.suite_manifest_path.exists():
        return
    now = datetime.now(timezone.utc).isoformat()
    data = {
        "suite_id": paths.bundle_id,
        "created_at": now,
        "updated_at": now,
        "cases": {},
    }
    paths.suite_manifest_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _update_suite_manifest(paths: BundlePaths, case_manifest: Dict[str, Any]) -> None:
    paths.suite_dir.mkdir(parents=True, exist_ok=True)

    data = _load_json(paths.suite_manifest_path) if paths.suite_manifest_path.exists() else {}
    if not data:
        now = datetime.now(timezone.utc).isoformat()
        data = {"suite_id": paths.bundle_id, "created_at": now, "updated_at": now, "cases": {}}

    data["suite_id"] = paths.bundle_id
    data["updated_at"] = datetime.now(timezone.utc).isoformat()

    # Case name: prefer manifest's repo runs_repo_name; fallback to folder name.
    case_name = (
        (case_manifest.get("repo") or {}).get("runs_repo_name")
        or (case_manifest.get("case") or {}).get("name")
        or paths.bundle_dir.name
    )

    rel_case_dir = str(paths.bundle_dir.relative_to(paths.suite_dir))
    rel_manifest = str(paths.manifest_path.relative_to(paths.suite_dir))
    rel_scans = str(paths.scans_dir.relative_to(paths.suite_dir))
    rel_analysis = str(paths.analysis_dir.relative_to(paths.suite_dir))

    scans = case_manifest.get("scans") or {}
    exit_codes = {k: (v or {}).get("exit_code") for k, v in scans.items()}

    data.setdefault("cases", {})
    data["cases"][case_name] = {
        "case_dir": rel_case_dir,
        "manifest": rel_manifest,
        "scans_dir": rel_scans,
        "analysis_dir": rel_analysis,
        "finished": (case_manifest.get("timestamps") or {}).get("finished"),
        "scanners_requested": case_manifest.get("scanners_requested") or [],
        "exit_codes": exit_codes,
    }

    paths.suite_manifest_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _write_suite_summary(paths: BundlePaths) -> None:
    """Write suite_dir/summary.csv with one row per case (best-effort)."""
    rows = []
    if not paths.cases_dir.exists():
        return

    for case_dir in sorted([p for p in paths.cases_dir.iterdir() if p.is_dir()], key=lambda p: p.name):
        mpath = case_dir / "run_manifest.json"
        if not mpath.exists():
            continue
        m = _load_json(mpath)
        case_name = (
            (m.get("repo") or {}).get("runs_repo_name")
            or (m.get("case") or {}).get("name")
            or case_dir.name
        )
        finished = (m.get("timestamps") or {}).get("finished")
        scanners_requested = m.get("scanners_requested") or []
        scans = m.get("scans") or {}

        ok = [t for t, v in scans.items() if (v or {}).get("exit_code") == 0]
        failed = [t for t, v in scans.items() if (v or {}).get("exit_code") not in (0, None)]

        analysis_ran = bool(m.get("analysis"))
        rel_case = str(case_dir.relative_to(paths.suite_dir))
        triage_csv = case_dir / "analysis" / "triage_queue.csv"
        rel_triage = str(triage_csv.relative_to(paths.suite_dir)) if triage_csv.exists() else ""

        rows.append(
            {
                "case": case_name,
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
            fieldnames=["case", "finished", "requested", "ok", "failed", "analysis", "case_dir", "triage_queue"],
        )
        writer.writeheader()
        writer.writerows(rows)
