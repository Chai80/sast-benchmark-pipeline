import csv
import json
import tempfile
import unittest
from pathlib import Path

from pipeline.analysis.analytics_mart import write_analytics_mart
from pipeline.analysis.suite.suite_triage_dataset import build_triage_dataset
from pipeline.analysis.suite.suite_triage_eval import build_triage_eval


class TestAnalyticsMartExport(unittest.TestCase):
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

    def _write_min_tool_run(self, case_dir: Path, *, suite_id: str, case_id: str) -> None:
        # Minimal v2 tool_runs layout for dim_tool_run export.
        run_dir = case_dir / "tool_runs" / "semgrep" / "r1"
        run_dir.mkdir(parents=True, exist_ok=True)

        run_json = {
            "schema_version": 2,
            "suite_id": suite_id,
            "case_id": case_id,
            "tool": "semgrep",
            "repo_name": "repo_x",
            "profile": "default",
            "run_id": "r1",
            "started": "2026-01-01T00:00:00Z",
            "finished": "2026-01-01T00:00:01Z",
            "exit_code": 0,
            "command": "semgrep --config auto",
            "artifacts": {
                "raw_dir": "raw",
                "metadata": "metadata.json",
                "config_receipt": "config_receipt.json",
                "normalized": "normalized.json",
            },
        }
        (run_dir / "run.json").write_text(json.dumps(run_json, indent=2), encoding="utf-8")

        meta = {
            "schema_version": 1,
            "tool": "semgrep",
            "scanner_version": "1.0.0",
            "scan_time_seconds": 0.5,
            "config_hash": "abc123",
        }
        (run_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

        conf = {
            "schema_version": 1,
            "suite_id": suite_id,
            "case_id": case_id,
            "tool": "semgrep",
            "repo_name": "repo_x",
            "profile": "default",
            "exit_code": 0,
            "command": "semgrep --config auto",
            "started": "2026-01-01T00:00:00Z",
            "finished": "2026-01-01T00:00:01Z",
        }
        (run_dir / "config_receipt.json").write_text(json.dumps(conf, indent=2), encoding="utf-8")

        norm = {
            "schema_version": 1,
            "tool": "semgrep",
            "repo_name": "repo_x",
            "run_id": "r1",
            "findings": [{"id": "f1"}, {"id": "f2"}],
        }
        (run_dir / "normalized.json").write_text(json.dumps(norm, indent=2), encoding="utf-8")

    def test_exports_tables(self) -> None:
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

            # Case 1
            case1 = cases_dir / "case_one"
            self._write_csv(
                case1 / "analysis" / "_tables" / "triage_features.csv",
                header=header,
                rows=[
                    {
                        "suite_id": suite_id,
                        "case_id": "case_one",
                        "cluster_id": "c1",
                        "tools_json": '["semgrep"]',
                        "tool_count": "1",
                        "max_severity_rank": "3",
                        "finding_count": "1",
                        "file_path": "a.py",
                        "start_line": "10",
                        "triage_rank": "1",
                        "gt_overlap": "1",
                        "gt_overlap_ids_json": '["GT-1"]',
                    }
                ],
            )
            self._write_gt_score(case1, ["GT-1"])
            self._write_min_tool_run(case1, suite_id=suite_id, case_id="case_one")

            # Case 2 (no tool run needed)
            case2 = cases_dir / "case_two"
            self._write_csv(
                case2 / "analysis" / "_tables" / "triage_features.csv",
                header=header,
                rows=[
                    {
                        "suite_id": suite_id,
                        "case_id": "case_two",
                        "cluster_id": "c1",
                        "tools_json": '["snyk"]',
                        "tool_count": "1",
                        "max_severity_rank": "3",
                        "finding_count": "1",
                        "file_path": "x.py",
                        "start_line": "1",
                        "triage_rank": "1",
                        "gt_overlap": "0",
                        "gt_overlap_ids_json": "[]",
                    }
                ],
            )
            self._write_gt_score(case2, ["GT-2"])

            # Build suite-level eval artifacts.
            build_triage_dataset(suite_dir=suite_dir)
            build_triage_eval(suite_dir=suite_dir, ks=[1])

            # Export analytics mart.
            res = write_analytics_mart(suite_dir=suite_dir)
            out_dir = Path(res["out_dir"])  # type: ignore[index]

            # Core tables
            self.assertTrue((out_dir / "dim_suite_run.csv").exists())
            self.assertTrue((out_dir / "dim_case.csv").exists())
            self.assertTrue((out_dir / "fact_eval_case_k.csv").exists())
            self.assertTrue((out_dir / "fact_eval_suite_k.csv").exists())
            self.assertTrue((out_dir / "fact_tool_value.csv").exists())
            self.assertTrue((out_dir / "dim_tool_run.csv").exists())
            self.assertTrue((out_dir / "analytics_mart_manifest.json").exists())

            # dim_tool_run should include our semgrep run.
            with (out_dir / "dim_tool_run.csv").open("r", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            tools = {r.get("tool") for r in rows}
            self.assertIn("semgrep", tools)


if __name__ == "__main__":
    unittest.main()
