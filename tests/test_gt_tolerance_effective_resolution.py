import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline.analysis.io.gt_tolerance_policy import resolve_effective_gt_tolerance
from pipeline.execution.analyze_mode import AnalyzeRequest, run_analyze
from pipeline.execution.run_case import RunRequest, _maybe_run_analysis
from pipeline.models import CaseSpec, RepoSpec
from pipeline.suites.layout import ensure_suite_dirs, get_suite_paths


class TestGTToleranceEffectiveResolution(unittest.TestCase):
    def test_resolve_effective_prefers_selection_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            suite_dir = Path(td) / "S1"
            (suite_dir / "analysis").mkdir(parents=True, exist_ok=True)

            (suite_dir / "suite.json").write_text(
                json.dumps(
                    {"plan": {"analysis": {"gt_tolerance_effective": 5}}}, indent=2
                )
                + "\n",
                encoding="utf-8",
            )

            (suite_dir / "analysis" / "gt_tolerance_selection.json").write_text(
                json.dumps(
                    {
                        "schema_version": "gt_tolerance_selection_v1",
                        "selected_gt_tolerance": 7,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            res = resolve_effective_gt_tolerance(suite_dir=suite_dir, requested=0)
            self.assertEqual(7, res["effective_gt_tolerance"])
            self.assertEqual("selection_json", res["source"])

    def test_resolve_effective_falls_back_to_suite_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            suite_dir = Path(td) / "S1"
            suite_dir.mkdir(parents=True, exist_ok=True)

            (suite_dir / "suite.json").write_text(
                json.dumps(
                    {"plan": {"analysis": {"gt_tolerance_effective": 5}}}, indent=2
                )
                + "\n",
                encoding="utf-8",
            )

            res = resolve_effective_gt_tolerance(suite_dir=suite_dir, requested=0)
            self.assertEqual(5, res["effective_gt_tolerance"])
            self.assertEqual("suite_json", res["source"])

    def test_analyze_mode_uses_suite_recorded_gt_tolerance_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            suite_root = root / "runs" / "suites"
            suite_dir = suite_root / "S1"
            case_dir = suite_dir / "cases" / "case1"
            (case_dir / "tool_runs").mkdir(parents=True, exist_ok=True)
            (suite_dir / "analysis").mkdir(parents=True, exist_ok=True)

            # Record an effective tolerance
            (suite_dir / "analysis" / "gt_tolerance_selection.json").write_text(
                json.dumps(
                    {
                        "schema_version": "gt_tolerance_selection_v1",
                        "selected_gt_tolerance": 7,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            called = {}

            def fake_run_suite(*, gt_tolerance: int, **kwargs):
                called["gt_tolerance"] = int(gt_tolerance)
                return {"ok": True, "gt_tolerance": int(gt_tolerance)}

            case = CaseSpec(
                case_id="case1", runs_repo_name="case1", label="case1", repo=RepoSpec()
            )

            req = AnalyzeRequest(
                metric="suite",
                case=case,
                suite_root=suite_root,
                suite_id="S1",
                case_path=str(case_dir),
                tools=("semgrep",),
                gt_tolerance=0,
                tolerance=3,
                gt_source="auto",
                analysis_filter="security",
                skip_suite_aggregate=False,
            )

            with patch("pipeline.analysis.analyze_suite.run_suite", new=fake_run_suite):
                rc = run_analyze(req)

            self.assertEqual(0, rc)
            self.assertEqual(7, called.get("gt_tolerance"))

    def test_analyze_mode_does_not_override_when_skip_suite_aggregate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            suite_root = root / "runs" / "suites"
            suite_dir = suite_root / "S1"
            case_dir = suite_dir / "cases" / "case1"
            (case_dir / "tool_runs").mkdir(parents=True, exist_ok=True)
            (suite_dir / "analysis").mkdir(parents=True, exist_ok=True)

            # Record an effective tolerance
            (suite_dir / "analysis" / "gt_tolerance_selection.json").write_text(
                json.dumps(
                    {
                        "schema_version": "gt_tolerance_selection_v1",
                        "selected_gt_tolerance": 7,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            called = {}

            def fake_run_suite(*, gt_tolerance: int, **kwargs):
                called["gt_tolerance"] = int(gt_tolerance)
                return {"ok": True, "gt_tolerance": int(gt_tolerance)}

            case = CaseSpec(
                case_id="case1", runs_repo_name="case1", label="case1", repo=RepoSpec()
            )

            req = AnalyzeRequest(
                metric="suite",
                case=case,
                suite_root=suite_root,
                suite_id="S1",
                case_path=str(case_dir),
                tools=("semgrep",),
                gt_tolerance=0,
                tolerance=3,
                gt_source="auto",
                analysis_filter="security",
                skip_suite_aggregate=True,
            )

            with patch("pipeline.analysis.analyze_suite.run_suite", new=fake_run_suite):
                rc = run_analyze(req)

            self.assertEqual(0, rc)
            self.assertEqual(0, called.get("gt_tolerance"))

    def test_benchmark_analysis_uses_suite_recorded_gt_tolerance(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            suite_root = root / "runs" / "suites"

            # Compute suite paths for a minimal suite layout
            paths = get_suite_paths(
                case_id="case1", suite_id="S1", suite_root=suite_root
            )
            ensure_suite_dirs(paths)

            # Suite-level analysis dir is created lazily by the pipeline; make it for the test.
            (paths.suite_dir / "analysis").mkdir(parents=True, exist_ok=True)

            # Record an effective tolerance at the suite level
            (paths.suite_dir / "analysis" / "gt_tolerance_selection.json").write_text(
                json.dumps(
                    {
                        "schema_version": "gt_tolerance_selection_v1",
                        "selected_gt_tolerance": 7,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            # Minimal tool run that satisfies find_latest_normalized_json
            run_id = "1234567890"  # matches RUN_ID_RE
            run_dir = paths.tool_runs_dir / "semgrep" / run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "normalized.json").write_text("{}\n", encoding="utf-8")

            called = {}

            def fake_run_suite(*, gt_tolerance: int, **kwargs):
                called["gt_tolerance"] = int(gt_tolerance)
                return {"ok": True, "gt_tolerance": int(gt_tolerance)}

            case = CaseSpec(
                case_id="case1", runs_repo_name="case1", label="case1", repo=RepoSpec()
            )
            req = RunRequest(
                invocation_mode="benchmark",
                case=case,
                repo_id="case1",
                scanners=("semgrep",),
                suite_root=suite_root,
                suite_id="S1",
                use_suite=True,
                gt_tolerance=0,
            )

            warnings: list[str] = []
            with patch("pipeline.analysis.analyze_suite.run_suite", new=fake_run_suite):
                out = _maybe_run_analysis(
                    req=req,
                    suite_paths=paths,
                    scanners=("semgrep",),
                    case_warnings=warnings,
                )

            self.assertIsInstance(out, dict)
            self.assertEqual(7, called.get("gt_tolerance"))


if __name__ == "__main__":
    unittest.main()
