from __future__ import annotations

from pathlib import Path

from pipeline.analysis.suite.gt_tolerance_sweep import disable_suite_calibration


def test_disable_suite_calibration_moves_into_checkpoints(tmp_path: Path) -> None:
    suite_dir = tmp_path / "suite"
    analysis_dir = suite_dir / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)

    cal_path = analysis_dir / "triage_calibration.json"
    cal_path.write_text('{"tool_weights": {}}', encoding="utf-8")

    disabled = disable_suite_calibration(suite_dir)

    assert disabled is not None
    assert disabled.exists()
    assert disabled.name == "triage_calibration.disabled.json"
    assert disabled.parent == analysis_dir / "_checkpoints"

    assert (
        not cal_path.exists()
    ), "triage_calibration.json should be removed after disable"
