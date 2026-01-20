import csv
import json
import tempfile
import unittest
from pathlib import Path

from pipeline.analysis.suite_triage_eval import build_triage_eval


class TestSuiteToolMarginalValue(unittest.TestCase):
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

    def test_drop_one_marginal_value_table(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            suite_id = "20260101T000000Z"
            suite_dir = root / "runs" / "suites" / suite_id

            # One case with 1 GT item.
            case_dir = suite_dir / "cases" / "case_one"
            self._write_gt_score(case_dir, ["GT-1"])

            # Dataset rows are clusters.
            # We intentionally make the "noise" cluster rank above the "good" cluster
            # so that removing the noisy tool improves Precision@1.
            header = [
                "suite_id",
                "case_id",
                "cluster_id",
                "tools_json",
                "tool_counts_json",
                "tool_count",
                "max_severity_rank",
                "finding_count",
                "file_path",
                "start_line",
                "triage_rank",
                "gt_overlap",
                "gt_overlap_ids_json",
            ]

            rows = [
                {
                    "suite_id": suite_id,
                    "case_id": "case_one",
                    "cluster_id": "c_noise",
                    "tools_json": '["noise"]',
                    "tool_counts_json": '{"noise": 1}',
                    "tool_count": "1",
                    "max_severity_rank": "3",
                    "finding_count": "1",
                    "file_path": "a.py",
                    "start_line": "10",
                    "triage_rank": "1",
                    "gt_overlap": "0",
                    "gt_overlap_ids_json": "[]",
                },
                {
                    "suite_id": suite_id,
                    "case_id": "case_one",
                    "cluster_id": "c_good",
                    "tools_json": '["good"]',
                    "tool_counts_json": '{"good": 1}',
                    "tool_count": "1",
                    "max_severity_rank": "2",
                    "finding_count": "1",
                    "file_path": "b.py",
                    "start_line": "20",
                    "triage_rank": "2",
                    "gt_overlap": "1",
                    "gt_overlap_ids_json": '["GT-1"]',
                },
            ]

            self._write_csv(suite_dir / "analysis" / "_tables" / "triage_dataset.csv", header=header, rows=rows)

            ev = build_triage_eval(suite_dir=suite_dir, suite_id=suite_id, ks=[1, 2])

            out_csv = Path(str(ev.get("out_tool_marginal_csv") or "")).resolve()
            self.assertTrue(out_csv.exists(), f"expected triage_tool_marginal.csv at {out_csv}")

            # Load rows keyed by (tool, strategy, k)
            by_key: dict[tuple[str, str, int], dict[str, str]] = {}
            with out_csv.open("r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for r in reader:
                    tool = str(r.get("tool") or "")
                    strat = str(r.get("strategy") or "")
                    k = int(r.get("k") or 0)
                    by_key[(tool, strat, k)] = dict(r)

            # Removing the noisy tool should improve Precision@1 (baseline).
            r_noise = by_key[("noise", "baseline", 1)]
            self.assertAlmostEqual(float(r_noise["precision_full"]), 0.0, places=6)
            self.assertAlmostEqual(float(r_noise["precision_drop"]), 1.0, places=6)
            self.assertAlmostEqual(float(r_noise["delta_precision"]), 1.0, places=6)
            self.assertEqual(int(r_noise["neg_in_topk_full"]), 1)
            self.assertEqual(int(r_noise["neg_in_topk_drop"]), 0)

            # Removing the good tool should reduce Coverage@2 (baseline) because the GT-positive cluster disappears.
            r_good = by_key[("good", "baseline", 2)]
            self.assertAlmostEqual(float(r_good["gt_coverage_full"]), 1.0, places=6)
            self.assertAlmostEqual(float(r_good["gt_coverage_drop"]), 0.0, places=6)
            self.assertAlmostEqual(float(r_good["delta_gt_coverage"]), -1.0, places=6)


if __name__ == "__main__":
    unittest.main()
