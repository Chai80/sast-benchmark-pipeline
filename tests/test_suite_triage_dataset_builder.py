import csv
import tempfile
import unittest
from pathlib import Path

from pipeline.analysis.suite_triage_dataset import build_triage_dataset


class TestSuiteTriageDatasetBuilder(unittest.TestCase):
    def _write_csv(self, path: Path, *, header: list[str], rows: list[dict[str, str]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=header)
            w.writeheader()
            for r in rows:
                w.writerow(r)

    def test_builds_dataset_and_reports_missing_and_empty_cases(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            suite_id = "20260101T000000Z"
            suite_dir = root / "runs" / "suites" / suite_id
            cases_dir = suite_dir / "cases"

            # Case 1: preferred layout (analysis/_tables/triage_features.csv)
            case1 = cases_dir / "case_one"
            header = [
                "suite_id",
                "case_id",
                "cluster_id",
                "schema_version",
                "generated_at",
                "repo_name",
                "tools_json",
                "tools",
                "tool_count",
                "suite_tool_count",
                "agreement_tool_ratio",
                "tool_counts_json",
                "finding_count",
                "severity_high_count",
                "severity_medium_count",
                "severity_low_count",
                "severity_unknown_count",
                "gt_overlap",
                "gt_overlap_count",
                "gt_overlap_ids_json",
                "gt_overlap_ids",
            ]
            self._write_csv(
                case1 / "analysis" / "_tables" / "triage_features.csv",
                header=header,
                rows=[
                    {
                        "suite_id": "",  # verify builder backfills
                        "case_id": "",  # verify builder backfills
                        "cluster_id": "c1",
                        "schema_version": "triage_features_v1",
                        "generated_at": "2026-01-01T00:00:00Z",
                        "repo_name": "repo1",
                        "tools_json": "[\"semgrep\",\"snyk\"]",
                        "tools": "semgrep,snyk",
                        "tool_count": "2",
                        "suite_tool_count": "4",
                        "agreement_tool_ratio": "0.5",
                        "tool_counts_json": "{\"semgrep\":1,\"snyk\":1}",
                        "finding_count": "2",
                        "severity_high_count": "1",
                        "severity_medium_count": "0",
                        "severity_low_count": "0",
                        "severity_unknown_count": "0",
                        "gt_overlap": "1",
                        "gt_overlap_count": "1",
                        "gt_overlap_ids_json": "[\"GT-1\"]",
                        "gt_overlap_ids": "GT-1",
                    }
                ],
            )

            # Case 2: legacy layout (analysis/triage_features.csv)
            case2 = cases_dir / "case_two"
            self._write_csv(
                case2 / "analysis" / "triage_features.csv",
                header=header,
                rows=[
                    {
                        "suite_id": suite_id,
                        "case_id": "case_two",
                        "cluster_id": "c2",
                        "schema_version": "triage_features_v1",
                        "generated_at": "2026-01-01T00:00:00Z",
                        "repo_name": "repo2",
                        "tools_json": "[\"sonar\"]",
                        "tools": "sonar",
                        "tool_count": "1",
                        "suite_tool_count": "4",
                        "agreement_tool_ratio": "0.25",
                        "tool_counts_json": "{\"sonar\":1}",
                        "finding_count": "1",
                        "severity_high_count": "0",
                        "severity_medium_count": "1",
                        "severity_low_count": "0",
                        "severity_unknown_count": "0",
                        "gt_overlap": "0",
                        "gt_overlap_count": "0",
                        "gt_overlap_ids_json": "[]",
                        "gt_overlap_ids": "",
                    }
                ],
            )

            # Case 3: empty triage_features.csv (header only)
            case3 = cases_dir / "case_three"
            self._write_csv(case3 / "analysis" / "_tables" / "triage_features.csv", header=header, rows=[])

            # Case 4: missing triage_features.csv entirely
            (cases_dir / "case_four").mkdir(parents=True, exist_ok=True)

            summary = build_triage_dataset(suite_dir=suite_dir)

            self.assertEqual(summary.get("suite_id"), suite_id)
            self.assertEqual(summary.get("rows"), 2)
            self.assertIn("case_four", summary.get("missing_cases") or [])
            self.assertIn("case_three", summary.get("empty_cases") or [])

            out_csv = Path(str(summary.get("out_csv")))
            self.assertTrue(out_csv.exists(), "Expected triage_dataset.csv to be written")

            with out_csv.open("r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                out_rows = list(reader)

            self.assertEqual(len(out_rows), 2)

            # Verify builder backfilled suite_id/case_id for case_one row.
            row_c1 = [r for r in out_rows if r.get("cluster_id") == "c1"][0]
            self.assertEqual(row_c1.get("suite_id"), suite_id)
            self.assertEqual(row_c1.get("case_id"), "case_one")

            # Ensure label columns are present in the output.
            self.assertIn("gt_overlap", reader.fieldnames or [])
            self.assertIn("gt_overlap_ids_json", reader.fieldnames or [])
