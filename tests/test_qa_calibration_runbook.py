import csv
import json
import tempfile
import unittest
from pathlib import Path


from pipeline.analysis.qa_calibration_runbook import all_ok, validate_calibration_suite_artifacts


class TestQACalibrationRunbook(unittest.TestCase):
    def _write_csv(self, path: Path, *, header: list[str], rows: list[dict[str, str]] | None = None) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=header)
            w.writeheader()
            for r in (rows or []):
                w.writerow(r)

    def test_validate_passes_when_all_artifacts_present(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            suite_dir = Path(td) / "runs" / "suites" / "20260101T000000Z"

            # Suite-level artifacts
            self._write_csv(
                suite_dir / "analysis" / "_tables" / "triage_dataset.csv",
                header=["suite_id", "case_id", "cluster_id"],
                rows=[{"suite_id": "20260101T000000Z", "case_id": "case1", "cluster_id": "c1"}],
            )

            (suite_dir / "analysis").mkdir(parents=True, exist_ok=True)
            (suite_dir / "analysis" / "triage_calibration.json").write_text(
                json.dumps(
                    {
                        "schema_version": "triage_calibration_v1",
                        "included_cases": ["case1"],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            self._write_csv(
                suite_dir / "analysis" / "_tables" / "triage_calibration_report.csv",
                header=["tool", "tp", "fp", "p_smoothed", "weight"],
                rows=[{"tool": "semgrep", "tp": "1", "fp": "0", "p_smoothed": "0.9", "weight": "1.0"}],
            )

            (suite_dir / "analysis" / "_tables" / "triage_eval_summary.json").write_text(
                json.dumps({"strategies": ["baseline", "agreement", "calibrated"]}, indent=2),
                encoding="utf-8",
            )

            # Tool contribution / marginal value outputs (suite-level)
            self._write_csv(
                suite_dir / "analysis" / "_tables" / "triage_tool_utility.csv",
                header=["suite_id", "tool", "gt_ids_covered", "unique_gt_ids", "neg_clusters", "exclusive_neg_clusters"],
                rows=[
                    {
                        "suite_id": "20260101T000000Z",
                        "tool": "semgrep",
                        "gt_ids_covered": "1",
                        "unique_gt_ids": "1",
                        "neg_clusters": "0",
                        "exclusive_neg_clusters": "0",
                    }
                ],
            )
            self._write_csv(
                suite_dir / "analysis" / "_tables" / "triage_tool_marginal.csv",
                header=[
                    "suite_id",
                    "tool",
                    "strategy",
                    "k",
                    "precision_full",
                    "precision_drop",
                    "delta_precision",
                    "gt_coverage_full",
                    "gt_coverage_drop",
                    "delta_gt_coverage",
                ],
                rows=[
                    {
                        "suite_id": "20260101T000000Z",
                        "tool": "semgrep",
                        "strategy": "baseline",
                        "k": "1",
                        "precision_full": "1.0",
                        "precision_drop": "0.0",
                        "delta_precision": "-1.0",
                        "gt_coverage_full": "1.0",
                        "gt_coverage_drop": "0.0",
                        "delta_gt_coverage": "-1.0",
                    }
                ],
            )

            # One case triage_queue.csv (schema check)
            self._write_csv(
                suite_dir / "cases" / "case1" / "analysis" / "_tables" / "triage_queue.csv",
                header=["rank", "triage_score_v1", "file_path"],
                rows=[{"rank": "1", "triage_score_v1": "0.1", "file_path": "a.py"}],
            )

            checks = validate_calibration_suite_artifacts(suite_dir)
            self.assertTrue(all_ok(checks))

    def test_validate_fails_when_required_artifacts_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            suite_dir = Path(td) / "runs" / "suites" / "20260101T000000Z"
            suite_dir.mkdir(parents=True, exist_ok=True)

            # Only write a triage_queue.csv; everything else should be missing.
            self._write_csv(
                suite_dir / "cases" / "case1" / "analysis" / "triage_queue.csv",
                header=["rank", "triage_score_v1", "file_path"],
                rows=[{"rank": "1", "triage_score_v1": "", "file_path": "a.py"}],
            )

            checks = validate_calibration_suite_artifacts(suite_dir)
            self.assertFalse(all_ok(checks))

            by_name = {c.name: c for c in checks}

            self.assertIn("analysis/_tables/triage_dataset.csv exists", by_name)
            self.assertFalse(by_name["analysis/_tables/triage_dataset.csv exists"].ok)

            self.assertIn("analysis/triage_calibration.json exists", by_name)
            self.assertFalse(by_name["analysis/triage_calibration.json exists"].ok)

            self.assertIn("analysis/_tables/triage_calibration_report.csv exists", by_name)
            self.assertFalse(by_name["analysis/_tables/triage_calibration_report.csv exists"].ok)

            self.assertIn("triage_eval_summary includes strategy calibrated", by_name)
            self.assertFalse(by_name["triage_eval_summary includes strategy calibrated"].ok)


if __name__ == "__main__":
    unittest.main()
