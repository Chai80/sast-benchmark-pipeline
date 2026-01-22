import csv
import json
import tempfile
import unittest
from pathlib import Path

from pipeline.analysis.suite.suite_triage_calibration import build_triage_calibration
from pipeline.analysis.suite.suite_triage_dataset import build_triage_dataset
from pipeline.analysis.suite.suite_triage_eval import build_triage_eval


class TestSuiteTriageEvalCalibratedStrategy(unittest.TestCase):
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

    def test_calibrated_strategy_breaks_single_tool_ties(self) -> None:
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
                "max_severity",
                "max_severity_rank",
                "finding_count",
                "file_path",
                "start_line",
                "triage_rank",
                "gt_overlap",
                "gt_overlap_ids_json",
            ]

            # One case, two single-tool clusters. Baseline and agreement both
            # would choose the first row (file-path tie-break), but calibration
            # should learn that goodtool is more precise than noisytool.
            case1 = cases_dir / "case_one"
            self._write_csv(
                case1 / "analysis" / "_tables" / "triage_features.csv",
                header=header,
                rows=[
                    {
                        "suite_id": suite_id,
                        "case_id": "case_one",
                        "cluster_id": "c_bad",
                        "tools_json": "[\"noisytool\"]",
                        "tool_count": "1",
                        "max_severity": "MEDIUM",
                        "max_severity_rank": "2",
                        "finding_count": "1",
                        "file_path": "a.py",
                        "start_line": "1",
                        "triage_rank": "1",
                        "gt_overlap": "0",
                        "gt_overlap_ids_json": "[]",
                    },
                    {
                        "suite_id": suite_id,
                        "case_id": "case_one",
                        "cluster_id": "c_good",
                        "tools_json": "[\"goodtool\"]",
                        "tool_count": "1",
                        "max_severity": "MEDIUM",
                        "max_severity_rank": "2",
                        "finding_count": "1",
                        "file_path": "b.py",
                        "start_line": "2",
                        "triage_rank": "2",
                        "gt_overlap": "1",
                        "gt_overlap_ids_json": "[\"GT-1\"]",
                    },
                ],
            )
            self._write_gt_score(case1, ["GT-1"])

            # Build suite-level artifacts.
            build_triage_dataset(suite_dir=suite_dir)
            build_triage_calibration(suite_dir=suite_dir)
            ev = build_triage_eval(suite_dir=suite_dir, ks=[1])

            strategies = ev.get("strategies") or []
            self.assertIn("calibrated", strategies)
            self.assertIn("calibrated_global", strategies)

            macro = ev.get("macro") or {}
            # Baseline chooses c_bad (triage_rank=1) -> precision@1=0
            self.assertAlmostEqual(float(macro["baseline"]["1"]["precision"]), 0.0, places=6)
            # Agreement tie-breaks by file_path -> a.py first -> precision@1=0
            self.assertAlmostEqual(float(macro["agreement"]["1"]["precision"]), 0.0, places=6)
            # Calibrated_global uses suite-level global weights (no OWASP segmentation) -> precision@1=1
            self.assertAlmostEqual(float(macro["calibrated_global"]["1"]["precision"]), 1.0, places=6)
            # Calibrated learns goodtool weight > noisytool and should pick c_good -> precision@1=1
            self.assertAlmostEqual(float(macro["calibrated"]["1"]["precision"]), 1.0, places=6)

            # New: delta summaries and per-case delta table should exist.
            delta = ev.get("delta_vs_baseline") or {}
            self.assertIn("macro", delta)
            self.assertIn("calibrated", delta.get("macro") or {})
            self.assertIn("calibrated_global", delta.get("macro") or {})
            self.assertAlmostEqual(float(delta["macro"]["calibrated"]["1"]["precision"]), 1.0, places=6)
            self.assertAlmostEqual(float(delta["macro"]["calibrated_global"]["1"]["precision"]), 1.0, places=6)

            deltas_csv = Path(str(ev.get("out_deltas_by_case_csv") or ""))
            self.assertTrue(deltas_csv.exists(), "Expected triage_eval_deltas_by_case.csv to be written")
            rows = list(csv.DictReader(deltas_csv.open("r", newline="", encoding="utf-8")))
            # One case, one K, and three non-baseline strategies (agreement + calibrated_global + calibrated).
            by_strat = {r.get("strategy"): r for r in rows if r.get("case_id") == "case_one" and r.get("k") == "1"}
            self.assertIn("calibrated", by_strat)
            self.assertIn("calibrated_global", by_strat)
            self.assertAlmostEqual(float(by_strat["calibrated"]["precision_delta"]), 1.0, places=6)
            self.assertAlmostEqual(float(by_strat["calibrated_global"]["precision_delta"]), 1.0, places=6)


if __name__ == "__main__":
    unittest.main()
