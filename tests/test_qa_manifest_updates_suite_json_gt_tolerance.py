from __future__ import annotations

import json
from pathlib import Path

from pipeline.analysis.qa_calibration_manifest import (
    GTTolerancePolicyRecord,
    build_qa_calibration_manifest,
    write_qa_calibration_manifest,
)


def test_write_qa_manifest_updates_suite_json_with_gt_tolerance(tmp_path: Path) -> None:
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir(parents=True, exist_ok=True)
    (suite_dir / "analysis").mkdir(parents=True, exist_ok=True)

    # Minimal suite.json (enough structure for the updater)
    suite_json_path = suite_dir / "suite.json"
    suite_json_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_run_id": "S",
                "suite_id": "S",
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
                "plan": {"analysis": {"tolerance": 3, "filter": "security"}},
                "cases": {},
            }
        ),
        encoding="utf-8",
    )

    gt_policy = GTTolerancePolicyRecord(
        initial_gt_tolerance=0,
        effective_gt_tolerance=10,
        sweep_enabled=True,
        sweep_candidates=[0, 1, 2, 3, 5, 10],
        auto_enabled=True,
        auto_min_fraction=0.95,
        selection_path=str((suite_dir / "analysis" / "gt_tolerance_selection.json").resolve()),
        sweep_report_csv=str((suite_dir / "analysis" / "_tables" / "gt_tolerance_sweep_report.csv").resolve()),
        sweep_payload_json=str((suite_dir / "analysis" / "gt_tolerance_sweep.json").resolve()),
        selection_warnings=[],
    )

    manifest = build_qa_calibration_manifest(
        suite_id="S",
        suite_dir=suite_dir,
        argv=["sast_cli.py", "--mode", "suite", "--qa-calibration"],
        scanners=["semgrep"],
        tolerance=3,
        analysis_filter="security",
        gt_source="auto",
        exclude_prefixes=[],
        include_harness=False,
        qa_scope="full",
        qa_owasp=None,
        qa_cases=None,
        qa_no_reanalyze=False,
        gt_policy=gt_policy,
        artifacts={},
        exit_code=0,
        checklist_pass=True,
    )

    _ = write_qa_calibration_manifest(suite_dir=suite_dir, manifest=manifest)

    updated = json.loads(suite_json_path.read_text(encoding="utf-8"))
    plan = updated.get("plan")
    assert isinstance(plan, dict)
    analysis = plan.get("analysis")
    assert isinstance(analysis, dict)

    assert analysis.get("gt_tolerance_initial") == 0
    assert analysis.get("gt_tolerance_effective") == 10
    assert analysis.get("gt_tolerance_mode") == "sweep_auto"
    assert analysis.get("gt_tolerance_sweep_candidates") == [0, 1, 2, 3, 5, 10]

    # Existing analysis tolerance should remain unchanged.
    assert analysis.get("tolerance") == 3
