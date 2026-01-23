"""pipeline.analysis.suite_triage_dataset

Suite-level triage dataset builder.

Near-term goal
--------------
Each *case* already emits a DS-friendly cluster-level feature table at:

  runs/suites/<suite_id>/cases/<case_id>/analysis/_tables/triage_features.csv

Some older runs may have written the CSV directly under analysis/.

This module aggregates all case-level triage_features.csv files into a single
suite-wide dataset suitable for calibration and evaluation:

  Output: runs/suites/<suite_id>/analysis/_tables/triage_dataset.csv

Design notes
------------
- Filesystem-first and deterministic.
- Missing/empty cases are explicitly reported (no silent skipping).
- Output columns are anchored to the per-case triage_features schema contract
  (TRIAGE_FEATURES_FIELDNAMES) when available.

This intentionally does NOT compute suite-level metrics. It only creates the
canonical table that later stages can consume.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from pipeline.analysis.io.write_artifacts import write_csv, write_json


# Import the triage_features schema contract if available.
# This keeps the dataset stable and DB/ETL friendly.
#
# Prefer importing from the compute layer to avoid pulling in stage registration
# side effects.
try:
    from pipeline.analysis.compute.triage_features import (  # type: ignore
        TRIAGE_FEATURES_FIELDNAMES,
        TRIAGE_FEATURES_SCHEMA_VERSION,
    )
except Exception:  # pragma: no cover
    TRIAGE_FEATURES_FIELDNAMES = []  # type: ignore
    TRIAGE_FEATURES_SCHEMA_VERSION = ""  # type: ignore


@dataclass(frozen=True)
class CaseTriageFeatures:
    case_id: str
    path: Path
    rows: List[Dict[str, Any]]
    fieldnames: List[str]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _discover_case_dirs(cases_dir: Path) -> List[Path]:
    if not cases_dir.exists() or not cases_dir.is_dir():
        return []
    out = [p for p in cases_dir.iterdir() if p.is_dir()]
    out.sort(key=lambda p: p.name)
    return out


def _triage_features_candidates(case_dir: Path) -> List[Path]:
    """Return candidate triage_features.csv paths (support both layouts)."""
    return [
        case_dir / "analysis" / "_tables" / "triage_features.csv",
        case_dir / "analysis" / "triage_features.csv",
    ]


def _discover_triage_features_csv(case_dir: Path) -> Optional[Path]:
    for p in _triage_features_candidates(case_dir):
        if p.exists() and p.is_file():
            return p
    return None


def _read_csv_rows(path: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Read a CSV into (rows, fieldnames).

    Notes
    -----
    - Uses csv.DictReader, so all values are read as strings.
    - Keeps the original header order.
    - Skips fully-empty rows.
    """

    with Path(path).open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = [str(x) for x in (reader.fieldnames or []) if x]

        rows: List[Dict[str, Any]] = []
        for row in reader:
            if not isinstance(row, dict):
                continue

            # DictReader may include a None key if a row has more columns than the header.
            cleaned: Dict[str, Any] = {}
            for k, v in row.items():
                if k is None:
                    continue
                cleaned[str(k)] = "" if v is None else v

            if any(str(v).strip() for v in cleaned.values()):
                rows.append(cleaned)

        return rows, fieldnames


def _merge_fieldnames(*fieldname_lists: Sequence[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for seq in fieldname_lists:
        for k in seq:
            kk = str(k)
            if not kk or kk in seen:
                continue
            seen.add(kk)
            out.append(kk)
    return out


def _stable_output_fieldnames(observed: Iterable[str]) -> List[str]:
    """Stable schema: known triage_features columns first, then extras."""

    observed_set = {str(x) for x in observed if str(x).strip()}

    # Keep the output schema stable across suites (and across older case runs)
    # by always including the full triage_features column contract when present.
    base: List[str] = list(TRIAGE_FEATURES_FIELDNAMES or [])

    # Minimal required keys (always include, even if schema import failed).
    required = ["suite_id", "case_id", "cluster_id"]

    # Preserve any extra columns that may have been added experimentally in
    # some case runs.
    extras = sorted([c for c in observed_set if c not in set(base)])

    out: List[str] = []
    for c in required + base + extras:
        if c in out:
            continue
        out.append(c)

    return out


def build_triage_dataset(
    *,
    suite_dir: Path,
    suite_id: Optional[str] = None,
    cases_dirname: str = "cases",
    out_dirname: str = "analysis",
) -> Dict[str, Any]:
    """Build a suite-level triage dataset CSV.

    Parameters
    ----------
    suite_dir:
        runs/suites/<suite_id>/
    suite_id:
        Optional override. Defaults to suite_dir.name.
    cases_dirname:
        Subdir under suite_dir containing case folders (default: "cases").
    out_dirname:
        Subdir under suite_dir to write suite-level analysis artifacts (default: "analysis").

    Returns
    -------
    A JSON-serializable summary dict.
    """

    suite_dir = Path(suite_dir).resolve()
    if not suite_dir.exists() or not suite_dir.is_dir():
        raise FileNotFoundError(f"suite_dir not found: {suite_dir}")

    sid = str(suite_id) if suite_id else suite_dir.name

    cases_dir = suite_dir / cases_dirname
    case_dirs = _discover_case_dirs(cases_dir)

    missing_cases: List[str] = []
    empty_cases: List[str] = []
    read_errors: List[Dict[str, str]] = []
    schema_mismatch_cases: List[Dict[str, str]] = []

    aggregated: List[Dict[str, Any]] = []
    observed_fieldnames: List[str] = []

    for case_dir in case_dirs:
        case_id = case_dir.name
        tf_path = _discover_triage_features_csv(case_dir)
        if tf_path is None:
            missing_cases.append(case_id)
            continue

        try:
            rows, header = _read_csv_rows(tf_path)
        except Exception as e:
            read_errors.append({"case_id": case_id, "path": str(tf_path), "error": str(e)})
            continue

        observed_fieldnames = _merge_fieldnames(observed_fieldnames, header)

        if not rows:
            empty_cases.append(case_id)
            continue

        # Schema version check (best-effort, warning only)
        if TRIAGE_FEATURES_SCHEMA_VERSION:
            v = str(rows[0].get("schema_version") or "").strip()
            if v and v != TRIAGE_FEATURES_SCHEMA_VERSION:
                schema_mismatch_cases.append({"case_id": case_id, "schema_version": v})

        for r in rows:
            # Track any new columns beyond the header (should not happen but supports DictReader quirks)
            observed_fieldnames = _merge_fieldnames(observed_fieldnames, r.keys())

            # Enforce stable IDs.
            if not str(r.get("suite_id") or "").strip():
                r["suite_id"] = sid
            if not str(r.get("case_id") or "").strip():
                r["case_id"] = case_id

            # Best-effort backfill schema_version for legacy rows.
            if TRIAGE_FEATURES_SCHEMA_VERSION and not str(r.get("schema_version") or "").strip():
                r["schema_version"] = TRIAGE_FEATURES_SCHEMA_VERSION

            aggregated.append(r)

    # Stable row order for diffs / reproducibility.
    aggregated.sort(key=lambda r: (str(r.get("case_id") or ""), str(r.get("cluster_id") or "")))

    out_dir = suite_dir / out_dirname
    out_csv = out_dir / "_tables" / "triage_dataset.csv"
    out_log = out_dir / "triage_dataset_build.log"
    out_summary = out_dir / "triage_dataset_build.json"

    # Build schema even if there are zero rows so downstream code has a stable file to read.
    fieldnames = _stable_output_fieldnames(observed_fieldnames or (TRIAGE_FEATURES_FIELDNAMES or []))

    write_csv(out_csv, aggregated, fieldnames=fieldnames)

    summary: Dict[str, Any] = {
        "suite_id": sid,
        "suite_dir": str(suite_dir),
        "cases_dir": str(cases_dir),
        "cases_total": len(case_dirs),
        "rows": len(aggregated),
        "out_csv": str(out_csv),
        "missing_cases": list(missing_cases),
        "empty_cases": list(empty_cases),
        "read_errors": list(read_errors),
        "schema_mismatch_cases": list(schema_mismatch_cases),
        "output_fieldnames": list(fieldnames),
        "built_at": _now_iso(),
    }

    # Persist a small build log for "no silent skipping".
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        lines: List[str] = []
        lines.append(f"[{summary['built_at']}] triage_dataset build")
        lines.append(f"suite_id     : {sid}")
        lines.append(f"suite_dir    : {suite_dir}")
        lines.append(f"cases_total  : {len(case_dirs)}")
        lines.append(f"rows_written : {len(aggregated)}")
        lines.append(f"out_csv      : {out_csv}")

        if missing_cases:
            lines.append("")
            lines.append(f"missing_cases ({len(missing_cases)}):")
            lines.extend([f"  - {cid}" for cid in missing_cases])

        if empty_cases:
            lines.append("")
            lines.append(f"empty_cases ({len(empty_cases)}):")
            lines.extend([f"  - {cid}" for cid in empty_cases])

        if read_errors:
            lines.append("")
            lines.append(f"read_errors ({len(read_errors)}):")
            for e in read_errors:
                lines.append(f"  - {e.get('case_id')}: {e.get('path')} :: {e.get('error')}")

        if schema_mismatch_cases:
            lines.append("")
            lines.append(f"schema_mismatch_cases ({len(schema_mismatch_cases)}):")
            for e in schema_mismatch_cases:
                lines.append(f"  - {e.get('case_id')}: schema_version={e.get('schema_version')}")

        out_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        # Best-effort: never prevent the dataset from being written.
        pass

    try:
        write_json(out_summary, summary)
    except Exception:
        pass

    return summary
