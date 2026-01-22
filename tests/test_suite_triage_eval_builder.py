import csv
import json
import tempfile
import unittest
from pathlib import Path

from pipeline.analysis.suite.suite_triage_dataset import build_triage_dataset
from pipeline.analysis.suite.suite_triage_eval import build_triage_eval


class TestSuiteTriageEvalBuilder(unittest.TestCase):
    def _write_csv(self, path: Path, *, header: list[str], rows: list[dict[str, str]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=header)
            w.writeheader()
            for r in rows:
                w.writerow(r)

    def _write_gt_score(self, case_dir: Path, gt_ids: list[str]) -> None:
        gt_dir = case_dir / "gt"
        gt_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "summary": {"total_gt_items": len(gt_ids)},
            "rows": [{"gt_id": gid} for gid in gt_ids],
        }
        (gt_dir / "gt_score.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def test_macro_vs_micro_scoring(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            suite_id = "20260101T000000Z"
            suite_dir = root / "runs" / "suites" / suite_id
            cases_dir = suite_dir / "cases"

            header = [
                "suite_id",
                "case_id",
                "cluster_id",
                "tools_json",
                "tool_count",
                "max_severity_rank",
                "finding_count",
                "file_path",
                "start_line",
                "triage_rank",
                "gt_overlap",
                "gt_overlap_ids_json",
            ]

            # Case 1: 3 clusters, 2 GT items.
            case1 = cases_dir / "case_one"
            self._write_csv(
                case1 / "analysis" / "_tables" / "triage_features.csv",
                header=header,
                rows=[
                    # Baseline top-1 (triage_rank=1) is a negative -> precision@1=0
                    {
                        "suite_id": suite_id,
                        "case_id": "case_one",
                        "cluster_id": "c2",
                        "tools_json": "[\"snyk\"]",
                        "tool_count": "1",
                        "max_severity_rank": "3",
                        "finding_count": "1",
                        "file_path": "a.py",
                        "start_line": "10",
                        "triage_rank": "1",
                        "gt_overlap": "0",
                        "gt_overlap_ids_json": "[]",
                    },
                    # Agreement top-1 (tool_count=2) is a positive -> precision@1=1
                    {
                        "suite_id": suite_id,
                        "case_id": "case_one",
                        "cluster_id": "c1",
                        "tools_json": "[\"semgrep\",\"snyk\"]",
                        "tool_count": "2",
                        "max_severity_rank": "3",
                        "finding_count": "2",
                        "file_path": "b.py",
                        "start_line": "20",
                        "triage_rank": "2",
                        "gt_overlap": "1",
                        "gt_overlap_ids_json": "[\"GT-1\"]",
                    },
                    {
                        "suite_id": suite_id,
                        "case_id": "case_one",
                        "cluster_id": "c3",
                        "tools_json": "[\"semgrep\"]",
                        "tool_count": "1",
                        "max_severity_rank": "2",
                        "finding_count": "1",
                        "file_path": "c.py",
                        "start_line": "30",
                        "triage_rank": "3",
                        "gt_overlap": "1",
                        "gt_overlap_ids_json": "[\"GT-2\"]",
                    },
                ],
            )
            self._write_gt_score(case1, ["GT-1", "GT-2"])

            # Case 2: 1 cluster, 1 GT item.
            case2 = cases_dir / "case_two"
            self._write_csv(
                case2 / "analysis" / "_tables" / "triage_features.csv",
                header=header,
                rows=[
                    {
                        "suite_id": suite_id,
                        "case_id": "case_two",
                        "cluster_id": "c1",
                        "tools_json": "[\"sonar\"]",
                        "tool_count": "1",
                        "max_severity_rank": "3",
                        "finding_count": "1",
                        "file_path": "x.py",
                        "start_line": "1",
                        "triage_rank": "1",
                        "gt_overlap": "1",
                        "gt_overlap_ids_json": "[\"GT-3\"]",
                    }
                ],
            )
            self._write_gt_score(case2, ["GT-3"])

            # Build dataset then eval (K=1 only to keep math simple).
            build_triage_dataset(suite_dir=suite_dir)
            ev = build_triage_eval(suite_dir=suite_dir, ks=[1])

            self.assertTrue(Path(str(ev.get("out_summary_json"))).exists())
            self.assertTrue(Path(str(ev.get("out_by_case_csv"))).exists())

            macro = ev.get("macro") or {}
            micro = ev.get("micro") or {}

            # Baseline: case1 precision@1=0, case2 precision@1=1 -> macro=0.5, micro=0.5
            self.assertAlmostEqual(float(macro["baseline"]["1"]["precision"]), 0.5, places=6)
            self.assertAlmostEqual(float(micro["baseline"]["1"]["precision"]), 0.5, places=6)

            # Baseline coverage@1: case1 covers 0/2, case2 covers 1/1 -> macro=(0+1)/2=0.5
            self.assertAlmostEqual(float(macro["baseline"]["1"]["gt_coverage"]), 0.5, places=6)
            # Micro coverage pools GT totals: covered=1, total=3 -> 0.333333...
            self.assertAlmostEqual(float(micro["baseline"]["1"]["gt_coverage"]), 1.0 / 3.0, places=6)

            # Agreement: case1 precision@1=1, case2 precision@1=1 -> macro=1, micro=1
            self.assertAlmostEqual(float(macro["agreement"]["1"]["precision"]), 1.0, places=6)
            self.assertAlmostEqual(float(micro["agreement"]["1"]["precision"]), 1.0, places=6)

            # Agreement coverage@1: case1 covers 1/2=0.5, case2 covers 1/1=1 -> macro=0.75
            self.assertAlmostEqual(float(macro["agreement"]["1"]["gt_coverage"]), 0.75, places=6)
            # Micro: covered=2, total=3 -> 0.666666...
            self.assertAlmostEqual(float(micro["agreement"]["1"]["gt_coverage"]), 2.0 / 3.0, places=6)


if __name__ == "__main__":
    unittest.main()
