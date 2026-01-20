import csv
import json
import tempfile
import unittest
from pathlib import Path

from pipeline.analysis.suite_triage_calibration import build_triage_calibration
from pipeline.analysis.suite_triage_dataset import build_triage_dataset
from pipeline.analysis.suite_triage_eval import build_triage_eval


class TestSuiteTriageEvalBaselineIsolation(unittest.TestCase):
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

    def test_baseline_ignores_triage_rank_when_calibration_exists(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            suite_id = "20260101T000000Z"
            suite_dir = root / "runs" / "suites" / suite_id
            cases_dir = suite_dir / "cases"
            case_dir = cases_dir / "case_one"

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

            # Intentionally set triage_rank to a *calibrated-like* ordering:
            # - The GT-negative row is rank=1
            # - The GT-positive row is rank=2
            #
            # Baseline strategy must NOT use triage_rank once a suite calibration exists,
            # otherwise baseline would be contaminated by calibrated ordering.
            self._write_csv(
                case_dir / "analysis" / "_tables" / "triage_features.csv",
                header=header,
                rows=[
                    {
                        "suite_id": suite_id,
                        "case_id": "case_one",
                        "cluster_id": "c_neg",
                        "tools_json": '["badtool"]',
                        "tool_count": "1",
                        "max_severity": "MEDIUM",
                        "max_severity_rank": "2",
                        "finding_count": "1",
                        "file_path": "b.py",
                        "start_line": "2",
                        "triage_rank": "1",
                        "gt_overlap": "0",
                        "gt_overlap_ids_json": "[]",
                    },
                    {
                        "suite_id": suite_id,
                        "case_id": "case_one",
                        "cluster_id": "c_pos",
                        "tools_json": '["goodtool"]',
                        "tool_count": "1",
                        "max_severity": "MEDIUM",
                        "max_severity_rank": "2",
                        "finding_count": "1",
                        "file_path": "a.py",
                        "start_line": "1",
                        "triage_rank": "2",
                        "gt_overlap": "1",
                        "gt_overlap_ids_json": '["GT-1"]',
                    },
                ],
            )
            self._write_gt_score(case_dir, ["GT-1"])

            build_triage_dataset(suite_dir=suite_dir)
            build_triage_calibration(suite_dir=suite_dir)
            ev = build_triage_eval(suite_dir=suite_dir, ks=[1])

            self.assertIn("calibrated", ev.get("strategies") or [])

            macro = ev.get("macro") or {}

            # With calibration present, baseline should IGNORE triage_rank and fall back to
            # the baseline tie-breaks (file_path asc among tied rows), selecting a.py first.
            self.assertAlmostEqual(float(macro["baseline"]["1"]["precision"]), 1.0, places=6)


if __name__ == "__main__":
    unittest.main()
