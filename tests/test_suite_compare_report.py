import csv
import json
import tempfile
import unittest
from pathlib import Path

from cli.utils.suite_picker import resolve_suite_dir_ref
from pipeline.analysis.suite.suite_compare_report import build_suite_compare_report


class TestSuiteCompareReport(unittest.TestCase):
    def _write_json(self, path: Path, obj: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj, indent=2), encoding="utf-8")

    def _write_csv(self, path: Path, header: list[str], rows: list[dict]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=header)
            w.writeheader()
            for r in rows:
                w.writerow(r)

    def _mk_suite(self, root: Path, suite_id: str, *, gt_tol: int, prec1: float) -> Path:
        suite_dir = root / "runs" / "suites" / suite_id
        (suite_dir / "cases" / "case_one").mkdir(parents=True, exist_ok=True)
        out_tables = suite_dir / "analysis" / "_tables"
        out_tables.mkdir(parents=True, exist_ok=True)

        # Minimal eval summary (required by compare)
        ev = {
            "suite_id": suite_id,
            "ks": [1],
            "strategies": ["baseline"],
            "micro": {"baseline": {"1": {"precision": prec1, "gt_coverage": 0.25}}},
            "macro": {"baseline": {"1": {"precision": prec1, "gt_coverage": 0.25}}},
        }
        self._write_json(out_tables / "triage_eval_summary.json", ev)

        # Minimal dataset
        ds_header = ["suite_id", "case_id", "cluster_id", "tools_json", "gt_overlap"]
        ds_rows = [
            {"suite_id": suite_id, "case_id": "case_one", "cluster_id": "c1", "tools_json": "[\"semgrep\"]", "gt_overlap": "1"},
            {"suite_id": suite_id, "case_id": "case_one", "cluster_id": "c2", "tools_json": "[\"sonar\"]", "gt_overlap": "0"},
        ]
        self._write_csv(out_tables / "triage_dataset.csv", ds_header, ds_rows)

        # Tool utility
        util_header = [
            "suite_id",
            "tool",
            "gt_ids_covered",
            "unique_gt_ids",
            "neg_clusters",
            "exclusive_neg_clusters",
        ]
        util_rows = [
            {
                "suite_id": suite_id,
                "tool": "semgrep",
                "gt_ids_covered": "1",
                "unique_gt_ids": "1",
                "neg_clusters": "0",
                "exclusive_neg_clusters": "0",
            },
            {
                "suite_id": suite_id,
                "tool": "sonar",
                "gt_ids_covered": "0",
                "unique_gt_ids": "0",
                "neg_clusters": "1",
                "exclusive_neg_clusters": "1",
            },
        ]
        self._write_csv(out_tables / "triage_tool_utility.csv", util_header, util_rows)

        # Minimal QA manifest containing GT tolerance policy (optional but useful for compare)
        manifest = {
            "schema_version": "qa_calibration_manifest_v1",
            "generated_at": "2026-01-01T00:00:00Z",
            "suite": {"suite_id": suite_id, "suite_dir": str(suite_dir)},
            "inputs": {
                "gt_tolerance_policy": {
                    "initial_gt_tolerance": gt_tol,
                    "effective_gt_tolerance": gt_tol,
                    "sweep": {"enabled": False, "candidates": [], "report_csv": None, "payload_json": None},
                    "auto": {"enabled": False, "min_fraction": None, "selection_path": None, "warnings": []},
                }
            },
        }
        self._write_json(suite_dir / "analysis" / "qa_manifest.json", manifest)

        # Minimal calibration json for global weights comparison (optional)
        cal = {
            "schema_version": "triage_calibration_v2",
            "tool_stats_global": [
                {"tool": "semgrep", "weight": 1.0},
                {"tool": "sonar", "weight": -0.5},
            ],
        }
        self._write_json(suite_dir / "analysis" / "triage_calibration.json", cal)

        return suite_dir

    def test_build_suite_compare_report_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            suite_a = self._mk_suite(root, "20260101T000000Z", gt_tol=0, prec1=0.5)
            suite_b = self._mk_suite(root, "20260102T000000Z", gt_tol=3, prec1=0.8)

            summary = build_suite_compare_report(suite_dir_a=suite_a, suite_dir_b=suite_b)
            out_csv = Path(str(summary["out_csv"]))
            out_json = Path(str(summary["out_json"]))

            self.assertTrue(out_csv.exists(), "Expected suite_compare_report.csv")
            self.assertTrue(out_json.exists(), "Expected suite_compare_report.json")

            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload.get("schema_version"), "suite_compare_report_v1")
            self.assertEqual(payload.get("suite_a", {}).get("suite_id"), "20260101T000000Z")
            self.assertEqual(payload.get("suite_b", {}).get("suite_id"), "20260102T000000Z")

            # Spot-check that policy delta shows up in the CSV.
            with out_csv.open("r", newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))

            tol_rows = [r for r in rows if r.get("section") == "policy" and r.get("name") == "effective_gt_tolerance"]
            self.assertTrue(tol_rows, "Expected a policy row for effective_gt_tolerance")
            self.assertEqual(tol_rows[0].get("a"), "0")
            self.assertEqual(tol_rows[0].get("b"), "3")

    def test_resolve_suite_dir_ref_latest_previous(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            suite_root = root / "runs" / "suites"
            (suite_root / "20260101T000000Z" / "cases").mkdir(parents=True)
            (suite_root / "20260102T000000Z" / "cases").mkdir(parents=True)

            # Use a file-based LATEST pointer (portable across platforms).
            (suite_root / "LATEST").write_text("20260102T000000Z", encoding="utf-8")

            latest = resolve_suite_dir_ref(suite_root, "latest")
            prev = resolve_suite_dir_ref(suite_root, "previous")

            self.assertIsNotNone(latest)
            self.assertIsNotNone(prev)
            self.assertEqual(Path(str(latest)).name, "20260102T000000Z")
            self.assertEqual(Path(str(prev)).name, "20260101T000000Z")


    def test_resolve_suite_dir_ref_latestqa_previousqa(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            suite_root = root / "runs" / "suites"

            # Two QA suites
            a = suite_root / "20260101T000000Z"
            b = suite_root / "20260102T000000Z"
            (a / "cases").mkdir(parents=True)
            (b / "cases").mkdir(parents=True)

            # Tag them as QA via suite_kind
            (a / "suite.json").write_text(json.dumps({"suite_id": "20260101T000000Z", "suite_kind": "qa_calibration"}), encoding="utf-8")
            (b / "suite.json").write_text(json.dumps({"suite_id": "20260102T000000Z", "suite_kind": "qa_calibration"}), encoding="utf-8")

            # Pointer
            (suite_root / "LATEST_QA").write_text("20260102T000000Z\n", encoding="utf-8")

            latest = resolve_suite_dir_ref(suite_root, "latestqa")
            prev = resolve_suite_dir_ref(suite_root, "previousqa")

            self.assertIsNotNone(latest)
            self.assertIsNotNone(prev)
            self.assertEqual(Path(str(latest)).name, "20260102T000000Z")
            self.assertEqual(Path(str(prev)).name, "20260101T000000Z")


if __name__ == "__main__":
    unittest.main()
