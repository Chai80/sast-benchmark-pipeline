from __future__ import annotations

"""pipeline.analysis.qa_calibration_manifest

Small, deterministic *QA manifest* for the triage calibration runbook.

What this is
------------
When you run the QA workflow (`--mode suite --qa-calibration`), the pipeline
produces several suite-level artifacts (dataset, calibration JSON, eval summary,
optional GT tolerance sweep/selection, and a PASS/FAIL checklist).

This manifest is a single, small JSON "receipt" that records:

- the effective GT tolerance policy (explicit vs sweep vs auto-selected)
- the key input knobs that influence suite-level calibration artifacts
- the canonical paths to artifacts produced by the runbook
- safe provenance like python version + pipeline git commit

Why it's important
------------------
CI and humans should not have to reconstruct "what happened" from logs and a
pile of output files.

`analysis/qa_manifest.json` makes QA runs:
- reproducible (inputs and selected tolerance are recorded)
- debuggable (artifact paths are indexed in one place)
- CI-friendly (one file to scrape/compare across runs)

Notes
-----
- This is *not* a replacement for suite.json/case.json.
- Keep this payload small and stable (no large tables embedded).
"""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from pipeline.suites.manifests import runtime_environment
from tools.io import write_json


QA_CALIBRATION_MANIFEST_SCHEMA_V1 = "qa_calibration_manifest_v1"

# Canonical filename for CI scraping.
QA_MANIFEST_FILENAME = "qa_manifest.json"

# Backwards-compatible alias (older tests/automation may look for this name).
QA_CALIBRATION_MANIFEST_LEGACY_FILENAME = "qa_calibration_manifest.json"


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _relpath_or_str(path: Optional[str | Path], *, base: Path) -> Optional[str]:
    if path is None:
        return None
    try:
        p = Path(str(path)).resolve()
        b = Path(base).resolve()
        return str(p.relative_to(b))
    except Exception:
        return str(path)


@dataclass(frozen=True)
class GTTolerancePolicyRecord:
    """A small record of the GT tolerance policy for a QA run."""

    initial_gt_tolerance: int
    effective_gt_tolerance: int

    sweep_enabled: bool
    sweep_candidates: Sequence[int]

    auto_enabled: bool
    auto_min_fraction: Optional[float]

    selection_path: Optional[str]
    sweep_report_csv: Optional[str]
    sweep_payload_json: Optional[str]

    selection_warnings: Sequence[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "initial_gt_tolerance": int(self.initial_gt_tolerance),
            "effective_gt_tolerance": int(self.effective_gt_tolerance),
            "sweep": {
                "enabled": bool(self.sweep_enabled),
                "candidates": [int(x) for x in (self.sweep_candidates or [])],
                "report_csv": self.sweep_report_csv,
                "payload_json": self.sweep_payload_json,
            },
            "auto": {
                "enabled": bool(self.auto_enabled),
                "min_fraction": float(self.auto_min_fraction) if self.auto_min_fraction is not None else None,
                "selection_path": self.selection_path,
                "warnings": list(self.selection_warnings or []),
            },
        }


def build_qa_calibration_manifest(
    *,
    suite_id: str,
    suite_dir: Path,
    argv: Sequence[str],
    scanners: Sequence[str],
    tolerance: int,
    analysis_filter: str,
    gt_source: str,
    exclude_prefixes: Sequence[str],
    include_harness: bool,
    qa_scope: Optional[str],
    qa_owasp: Optional[str],
    qa_cases: Optional[str],
    qa_no_reanalyze: bool,
    gt_policy: GTTolerancePolicyRecord,
    artifacts: Mapping[str, Optional[str]],
    exit_code: int,
    checklist_pass: Optional[bool],
) -> Dict[str, Any]:
    """Build a JSON-serializable manifest payload.

    Notes
    -----
    - Keep this dict small and stable; avoid embedding large tables.
    - Avoid absolute paths where possible (use paths relative to suite_dir).
    """

    suite_dir = Path(suite_dir).resolve()

    # Normalize artifact paths relative to suite_dir for portability.
    artifacts_rel: Dict[str, Optional[str]] = {}
    for k, v in dict(artifacts or {}).items():
        artifacts_rel[str(k)] = _relpath_or_str(v, base=suite_dir) if v else None

    payload: Dict[str, Any] = {
        "schema_version": QA_CALIBRATION_MANIFEST_SCHEMA_V1,
        "generated_at": _now_iso_utc(),
        "suite": {
            "suite_id": str(suite_id),
            "suite_dir": str(suite_dir),
        },
        "invocation": {
            "argv": list(argv),
            "environment": runtime_environment(),
        },
        "inputs": {
            "scanners": list(scanners),
            "analysis": {
                "tolerance": int(tolerance),
                "analysis_filter": str(analysis_filter),
                "gt_source": str(gt_source),
                "exclude_prefixes": list(exclude_prefixes or ()),
                "include_harness": bool(include_harness),
            },
            "qa": {
                "scope": str(qa_scope) if qa_scope is not None else None,
                "owasp": str(qa_owasp) if qa_owasp is not None else None,
                "cases": str(qa_cases) if qa_cases is not None else None,
                "no_reanalyze": bool(qa_no_reanalyze),
            },
            "gt_tolerance_policy": gt_policy.to_dict(),
        },
        "artifacts": artifacts_rel,
        "result": {
            "exit_code": int(exit_code),
            "checklist_pass": bool(checklist_pass) if checklist_pass is not None else None,
        },
    }
    return payload


def write_qa_calibration_manifest(
    *,
    suite_dir: Path,
    manifest: Mapping[str, Any],
    filename: str = QA_MANIFEST_FILENAME,
    legacy_aliases: Sequence[str] = (QA_CALIBRATION_MANIFEST_LEGACY_FILENAME,),
) -> Path:
    """Write the QA manifest under runs/suites/<suite_id>/analysis/.

    Canonical path:
      runs/suites/<suite_id>/analysis/qa_manifest.json

    For backward compatibility, we also write a copy to any filenames listed in
    `legacy_aliases` (by default: qa_calibration_manifest.json).

    Uses atomic replace via tools.io.write_json.
    """

    suite_dir = Path(suite_dir).resolve()
    analysis_dir = (suite_dir / "analysis").resolve()

    out_path = (analysis_dir / filename).resolve()

    # Ensure JSON serializability early so callers don't write a partial file.
    _ = json.dumps(manifest)

    write_json(out_path, dict(manifest))

    # Optional compatibility aliases.
    for alias in (legacy_aliases or ()):  # type: ignore[truthy-bool]
        a = str(alias).strip()
        if not a:
            continue
        if a == filename:
            continue
        alias_path = (analysis_dir / a).resolve()
        try:
            write_json(alias_path, dict(manifest))
        except Exception:
            # Best-effort: the canonical file is the one CI should scrape.
            pass

    return out_path
