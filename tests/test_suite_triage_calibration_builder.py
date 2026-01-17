import csv
import json
import tempfile
import unittest
from pathlib import Path

from pipeline.analysis.suite_triage_calibration import build_triage_calibration


class TestSuiteTriageCalibrationBuilder(unittest.TestCase):
    def _write_csv(self, path: Path, *, header: list[str], rows: list[dict[str, str]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=header)
            w.writeheader()
            for r in rows:
                w.writerow(r)

    def _write_gt_score(self, case_dir: Path) -> None:
        gt_dir = case_dir / "gt"
        gt_dir.mkdir(parents=True, exist_ok=True)
        payload = {"summary": {"total_gt_items": 1}, "rows": [{"gt_id": "GT-1"}]}
        (gt_dir / "gt_score.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def test_builds_calibration_excludes_no_gt_and_sorts_tools(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            suite_id = "20260101T000000Z"
            suite_dir = root / "runs" / "suites" / suite_id

            # triage_dataset.csv input
            header = [
                "suite_id",
                "case_id",
                "cluster_id",
                "tools_json",
                "tools",
                "gt_overlap",
            ]

            dataset_path = suite_dir / "analysis" / "_tables" / "triage_dataset.csv"
            self._write_csv(
                dataset_path,
                header=header,
                rows=[
                    # case_one (has GT): semgrep positive
                    {
                        "suite_id": suite_id,
                        "case_id": "case_one",
                        "cluster_id": "c1",
                        "tools_json": "[\"semgrep\"]",
                        "tools": "semgrep",
                        "gt_overlap": "1",
                    },
                    # case_one (has GT): semgrep+snyk negative
                    {
                        "suite_id": suite_id,
                        "case_id": "case_one",
                        "cluster_id": "c2",
                        "tools_json": "[\"semgrep\",\"snyk\"]",
                        "tools": "semgrep,snyk",
                        "gt_overlap": "0",
                    },
                    # case_two (has GT): sonar negative (no overlaps in case -> suspicious)
                    {
                        "suite_id": suite_id,
                        "case_id": "case_two",
                        "cluster_id": "c1",
                        "tools_json": "[\"sonar\"]",
                        "tools": "sonar",
                        "gt_overlap": "0",
                    },
                    # case_three (NO GT): should be excluded from learning
                    {
                        "suite_id": suite_id,
                        "case_id": "case_three",
                        "cluster_id": "c1",
                        "tools_json": "[\"snyk\"]",
                        "tools": "snyk",
                        "gt_overlap": "1",
                    },
                ],
            )

            # GT presence gate
            self._write_gt_score(suite_dir / "cases" / "case_one")
            self._write_gt_score(suite_dir / "cases" / "case_two")
            # no GT for case_three

            summary = build_triage_calibration(suite_dir=suite_dir)
            out_json = Path(str(summary.get("out_json")))
            self.assertTrue(out_json.exists(), "Expected triage_calibration.json to be written")

            cal = json.loads(out_json.read_text(encoding="utf-8"))

            # Exclusions
            self.assertEqual(cal.get("included_cases"), ["case_one", "case_two"])
            self.assertEqual(cal.get("excluded_cases_no_gt"), ["case_three"])

            # Suspicious cases should include case_two (GT present but 0 overlaps)
            suspicious = cal.get("suspicious_cases") or []
            suspicious_ids = [s.get("case_id") for s in suspicious if isinstance(s, dict)]
            self.assertIn("case_two", suspicious_ids)

            # Tool stats: sorted tool list, computed TP/FP and smoothed precision.
            tool_stats = cal.get("tool_stats") or []
            tools = [t.get("tool") for t in tool_stats if isinstance(t, dict)]
            self.assertEqual(tools, sorted(tools))

            by_tool = {t["tool"]: t for t in tool_stats if isinstance(t, dict) and t.get("tool")}

            # semgrep: tp=1 fp=1 => p=0.5 => weight ~ 0
            self.assertEqual(int(by_tool["semgrep"]["tp"]), 1)
            self.assertEqual(int(by_tool["semgrep"]["fp"]), 1)
            self.assertAlmostEqual(float(by_tool["semgrep"]["p_smoothed"]), 0.5, places=6)
            self.assertAlmostEqual(float(by_tool["semgrep"]["weight"]), 0.0, places=6)

            # snyk: tp=0 fp=1 => p=1/3 => weight=log(0.5)=-0.693147...
            self.assertEqual(int(by_tool["snyk"]["tp"]), 0)
            self.assertEqual(int(by_tool["snyk"]["fp"]), 1)
            self.assertAlmostEqual(float(by_tool["snyk"]["p_smoothed"]), 1.0 / 3.0, places=6)
            self.assertAlmostEqual(float(by_tool["snyk"]["weight"]), -0.693147, places=6)

            # sonar: tp=0 fp=1 => p=1/3
            self.assertEqual(int(by_tool["sonar"]["tp"]), 0)
            self.assertEqual(int(by_tool["sonar"]["fp"]), 1)
            self.assertAlmostEqual(float(by_tool["sonar"]["p_smoothed"]), 1.0 / 3.0, places=6)

            # Report CSV is optional but enabled by default.
            out_report = Path(str(summary.get("out_report_csv")))
            self.assertTrue(out_report.exists(), "Expected triage_calibration_report.csv to be written")


if __name__ == "__main__":
    unittest.main()
