import argparse
import csv
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any, List, Optional, Set

from cli.commands.suite import run_suite_mode
from pipeline.suites.bundles import safe_name


class FakePipeline:
    """A minimal pipeline stub used to test QA runbook wiring.

    The QA calibration flow is mostly filesystem-first: it expects per-case
    triage_features.csv + gt artifacts, then builds suite-level dataset /
    calibration / eval, then re-analyzes to populate per-case triage_queue.csv
    with triage_score_v1.

    This stub avoids running any real scanners by emitting the minimum artifacts
    the suite-level builders and QA checklist consume.
    """

    def __init__(
        self,
        *,
        nonempty_score: bool = True,
        fail_on_gt_tolerance: Optional[Set[int]] = None,
        ambiguous_gt: bool = False,
    ) -> None:
        self.nonempty_score = bool(nonempty_score)
        self.fail_on_gt_tolerance: Set[int] = set(fail_on_gt_tolerance or set())
        self.ambiguous_gt = bool(ambiguous_gt)
        self.run_calls: List[Any] = []
        self.analyze_calls: List[Any] = []

    def run(self, req: Any) -> int:
        self.run_calls.append(req)

        suite_root = Path(req.suite_root)
        suite_id = safe_name(str(req.suite_id))
        case_id = safe_name(str(req.case.case_id))

        suite_dir = suite_root / suite_id
        case_dir = suite_dir / "cases" / case_id

        # --- Minimal tool_runs + config_receipt.json -----------------------
        # The real pipeline writes a config receipt per tool run.
        # The QA runbook expects these to exist so profile/config becomes a
        # tracked, suite-visible variable.
        scanners = getattr(req, "scanners", None) or getattr(req, "scanners_requested", None) or []
        profile = getattr(req, "profile", None) or "default"
        for tool in [str(t).strip() for t in (scanners or []) if str(t).strip()]:
            tr_dir = case_dir / "tool_runs" / tool / "R1"
            tr_dir.mkdir(parents=True, exist_ok=True)
            (tr_dir / "config_receipt.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "tool": tool,
                        "profile": str(profile),
                        "artifacts": {"rules_inventory": None},
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

        # --- Per-case triage features (input to suite dataset builder) ------
        tables_dir = case_dir / "analysis" / "_tables"
        tables_dir.mkdir(parents=True, exist_ok=True)

        tf_path = tables_dir / "triage_features.csv"

        # Minimal subset of the stable triage_features schema.
        fieldnames = [
            "suite_id",
            "case_id",
            "cluster_id",
            "schema_version",
            "generated_at",
            "owasp_id",
            "file_path",
            "start_line",
            "end_line",
            "tool_count",
            "finding_count",
            "tools_json",
            "tools",
            "max_severity",
            "max_severity_rank",
            "gt_overlap",
            "gt_overlap_ids_json",
        ]

        # Two clusters. In normal mode, one is GT-positive and one GT-negative.
        # In ambiguous_gt mode, we simulate tolerance-induced ambiguity by making:
        # - c1 overlap multiple GT IDs (many-to-one)
        # - c2 overlap a GT ID already used by c1 (one-to-many)
        if self.ambiguous_gt:
            rows = [
                {
                    "suite_id": suite_id,
                    "case_id": case_id,
                    "cluster_id": "c1",
                    "schema_version": "triage_features_v1",
                    "generated_at": "2026-01-01T00:00:00Z",
                    "owasp_id": case_id,
                    "file_path": "src/app.py",
                    "start_line": "10",
                    "end_line": "10",
                    "tool_count": "1",
                    "finding_count": "1",
                    "tools_json": json.dumps(["semgrep"]),
                    "tools": "semgrep",
                    "max_severity": "HIGH",
                    "max_severity_rank": "3",
                    "gt_overlap": "1",
                    "gt_overlap_ids_json": json.dumps(["GT1", "GT2"]),
                },
                {
                    "suite_id": suite_id,
                    "case_id": case_id,
                    "cluster_id": "c2",
                    "schema_version": "triage_features_v1",
                    "generated_at": "2026-01-01T00:00:00Z",
                    "owasp_id": case_id,
                    "file_path": "src/lib.py",
                    "start_line": "20",
                    "end_line": "20",
                    "tool_count": "1",
                    "finding_count": "1",
                    "tools_json": json.dumps(["snyk"]),
                    "tools": "snyk",
                    "max_severity": "LOW",
                    "max_severity_rank": "1",
                    "gt_overlap": "1",
                    "gt_overlap_ids_json": json.dumps(["GT1"]),
                },
            ]
        else:
            rows = [
                {
                    "suite_id": suite_id,
                    "case_id": case_id,
                    "cluster_id": "c1",
                    "schema_version": "triage_features_v1",
                    "generated_at": "2026-01-01T00:00:00Z",
                    "owasp_id": case_id,
                    "file_path": "src/app.py",
                    "start_line": "10",
                    "end_line": "10",
                    "tool_count": "1",
                    "finding_count": "1",
                    "tools_json": json.dumps(["semgrep"]),
                    "tools": "semgrep",
                    "max_severity": "HIGH",
                    "max_severity_rank": "3",
                    "gt_overlap": "1",
                    "gt_overlap_ids_json": json.dumps(["GT1"]),
                },
                {
                    "suite_id": suite_id,
                    "case_id": case_id,
                    "cluster_id": "c2",
                    "schema_version": "triage_features_v1",
                    "generated_at": "2026-01-01T00:00:00Z",
                    "owasp_id": case_id,
                    "file_path": "src/lib.py",
                    "start_line": "20",
                    "end_line": "20",
                    "tool_count": "1",
                    "finding_count": "1",
                    "tools_json": json.dumps(["snyk"]),
                    "tools": "snyk",
                    "max_severity": "LOW",
                    "max_severity_rank": "1",
                    "gt_overlap": "0",
                    "gt_overlap_ids_json": json.dumps([]),
                },
            ]

        with tf_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in rows:
                w.writerow(r)

        # --- Per-case GT gate artifact (used to include cases in calibration) ---
        gt_dir = case_dir / "gt"
        gt_dir.mkdir(parents=True, exist_ok=True)
        gt_rows = [
            {
                "gt_id": "GT1",
                "file_path": "src/app.py",
                "start_line": 10,
                "end_line": 10,
            }
        ]
        if self.ambiguous_gt:
            gt_rows.append(
                {
                    "gt_id": "GT2",
                    "file_path": "src/app.py",
                    "start_line": 10,
                    "end_line": 10,
                }
            )

        (gt_dir / "gt_score.json").write_text(
            json.dumps(
                {
                    "schema_version": "gt_score_v1",
                    "rows": gt_rows,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        # NOTE: Do NOT write triage_queue.csv here.
        # The whole point of the QA runbook is that re-analysis is required
        # for per-case triage_queue.csv to pick up suite-level calibration.

        return 0

    def analyze(self, req: Any) -> int:
        self.analyze_calls.append(req)

        gt_tol = int(getattr(req, "gt_tolerance", 0) or 0)
        if gt_tol in self.fail_on_gt_tolerance:
            raise RuntimeError(f"simulated analyze failure (gt_tolerance={gt_tol})")

        case_dir = Path(str(req.case_path)).resolve()
        tables_dir = case_dir / "analysis" / "_tables"
        tables_dir.mkdir(parents=True, exist_ok=True)

        tq_path = tables_dir / "triage_queue.csv"
        fieldnames = [
            "triage_rank",
            "file_path",
            "start_line",
            "triage_score_v1",
        ]

        score = "1.000000" if self.nonempty_score else ""

        with tq_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerow(
                {
                    "triage_rank": "1",
                    "file_path": "src/app.py",
                    "start_line": "10",
                    "triage_score_v1": score,
                }
            )

        return 0


class TestCLISuiteQACalibrationWiring(unittest.TestCase):
    def _make_minimal_worktrees_root(self, root: Path) -> Path:
        worktrees_root = root / "worktrees"
        worktrees_root.mkdir(parents=True, exist_ok=True)

        # The suite loader only requires a `.git` marker.
        for case_id in ["A03", "A07"]:
            repo_dir = worktrees_root / case_id
            repo_dir.mkdir(parents=True, exist_ok=True)
            (repo_dir / ".git").mkdir(parents=True, exist_ok=True)
            (repo_dir / "README.md").write_text("demo\n", encoding="utf-8")

        return worktrees_root

    def _make_args(
        self, *, suite_root: Path, worktrees_root: Path, suite_id: str
    ) -> argparse.Namespace:
        # NOTE: The suite command has many CLI flags. This only populates
        # the fields used by run_suite_mode.
        return argparse.Namespace(
            # Suite layout
            no_suite=False,
            suite_root=str(suite_root),
            suite_id=suite_id,
            # Suite sources
            suite_file=None,
            cases_from=None,
            worktrees_root=str(worktrees_root),
            max_cases=None,
            repo_url=None,
            branches=None,
            # Execution
            scanners="semgrep,snyk,sonar",
            dry_run=False,
            quiet=True,
            skip_analysis=False,
            tolerance=0,
            analysis_filter="security",
            # Tool overrides (required fields in suite.py)
            sonar_project_key=None,
            aikido_git_ref=None,
            # QA flags
            qa_calibration=True,
            qa_scope="smoke",
            qa_owasp=None,
            qa_cases=None,
            qa_no_reanalyze=False,
            # GT knobs
            gt_tolerance=0,
            gt_source="auto",
            # (QA) Optional deterministic sweep + auto-selection
            gt_tolerance_sweep=None,
            gt_tolerance_auto=False,
            gt_tolerance_auto_min_fraction=0.95,
            # Analysis selectors
            exclude_prefixes=(),
            include_harness=False,
        )

    def test_qa_calibration_runbook_wires_second_analyze_pass(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            worktrees_root = self._make_minimal_worktrees_root(root)
            suite_root = root / "runs" / "suites"
            suite_id = "qa_wiring_pass"

            args = self._make_args(
                suite_root=suite_root,
                worktrees_root=worktrees_root,
                suite_id=suite_id,
            )

            pipeline = FakePipeline(nonempty_score=True)

            buf = StringIO()
            with redirect_stdout(buf):
                rc = int(run_suite_mode(args, pipeline, repo_registry={}))

            self.assertEqual(rc, 0, f"Expected success. Output:\n{buf.getvalue()}")

            suite_dir = suite_root / safe_name(suite_id)
            checklist_path = suite_dir / "analysis" / "qa_calibration_checklist.txt"
            self.assertTrue(checklist_path.exists(), "Expected checklist file to be written")
            checklist = checklist_path.read_text(encoding="utf-8")
            self.assertIn("Overall: PASS", checklist)

            # The key regression assertion: the QA workflow must trigger the second
            # analyze pass (otherwise triage_queue.csv cannot have triage_score_v1).
            self.assertEqual(
                len(pipeline.analyze_calls),
                2,
                "Expected analyze() to run once per case",
            )

            # The suite-level outputs should also exist.
            self.assertTrue((suite_dir / "analysis" / "_tables" / "triage_dataset.csv").exists())
            self.assertTrue((suite_dir / "analysis" / "triage_calibration.json").exists())
            self.assertTrue(
                (suite_dir / "analysis" / "_tables" / "triage_eval_summary.json").exists()
            )

            # Suite classification + pointer: QA calibration runs should be tagged
            # and update runs/suites/LATEST_QA for deterministic selection.
            suite_json = json.loads((suite_dir / "suite.json").read_text(encoding="utf-8"))
            self.assertEqual(suite_json.get("suite_kind"), "qa_calibration")

            latest_qa = suite_root / "LATEST_QA"
            self.assertTrue(latest_qa.exists(), "Expected LATEST_QA pointer to exist")
            self.assertEqual(latest_qa.read_text(encoding="utf-8").strip(), safe_name(suite_id))

    def test_qa_calibration_checklist_failure_returns_nonzero(self) -> None:
        """If triage_score_v1 is never populated, the QA runbook must FAIL."""

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            worktrees_root = self._make_minimal_worktrees_root(root)
            suite_root = root / "runs" / "suites"
            suite_id = "qa_wiring_fail"

            args = self._make_args(
                suite_root=suite_root,
                worktrees_root=worktrees_root,
                suite_id=suite_id,
            )

            pipeline = FakePipeline(nonempty_score=False)

            buf = StringIO()
            with redirect_stdout(buf):
                rc = int(run_suite_mode(args, pipeline, repo_registry={}))

            self.assertNotEqual(rc, 0, "Expected non-zero exit code for failed QA checklist")

            suite_dir = suite_root / safe_name(suite_id)
            checklist_path = suite_dir / "analysis" / "qa_calibration_checklist.txt"
            self.assertTrue(checklist_path.exists(), "Expected checklist file to be written")
            checklist = checklist_path.read_text(encoding="utf-8")
            self.assertIn("Overall: FAIL", checklist)

    def test_qa_calibration_sweep_auto_writes_selection_and_manifest(self) -> None:
        """QA calibration with GT tolerance sweep/auto should persist sweep+selection+manifest artifacts."""

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            worktrees_root = self._make_minimal_worktrees_root(root)
            suite_root = root / "runs" / "suites"
            suite_id = "qa_sweep_auto"

            args = self._make_args(
                suite_root=suite_root,
                worktrees_root=worktrees_root,
                suite_id=suite_id,
            )

            # Enable sweep + auto-selection.
            args.gt_tolerance_sweep = "0,1"
            args.gt_tolerance_auto = True
            args.gt_tolerance_auto_min_fraction = 0.95

            pipeline = FakePipeline(nonempty_score=True)

            buf = StringIO()
            with redirect_stdout(buf):
                rc = int(run_suite_mode(args, pipeline, repo_registry={}))

            self.assertEqual(rc, 0, f"Expected success. Output:\n{buf.getvalue()}")

            suite_dir = suite_root / safe_name(suite_id)

            # Sweep artifacts
            self.assertTrue(
                (suite_dir / "analysis" / "_tables" / "gt_tolerance_sweep_report.csv").exists(),
                "Expected sweep report CSV",
            )
            self.assertTrue(
                (suite_dir / "analysis" / "gt_tolerance_sweep.json").exists(),
                "Expected sweep JSON payload",
            )

            # Selection artifact
            sel_path = suite_dir / "analysis" / "gt_tolerance_selection.json"
            self.assertTrue(sel_path.exists(), "Expected gt_tolerance_selection.json")
            sel = json.loads(sel_path.read_text(encoding="utf-8"))
            self.assertEqual(
                sel.get("selected_gt_tolerance"),
                0,
                "With identical rows, auto should pick smallest",
            )

            # QA manifest artifact (canonical)
            manifest_path = suite_dir / "analysis" / "qa_manifest.json"
            self.assertTrue(manifest_path.exists(), "Expected qa_manifest.json")
            man = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(man.get("schema_version"), "qa_calibration_manifest_v1")
            gt_policy = (man.get("inputs") or {}).get("gt_tolerance_policy") or {}
            self.assertEqual(gt_policy.get("effective_gt_tolerance"), 0)
            sweep = gt_policy.get("sweep") or {}
            self.assertEqual(sweep.get("candidates"), [0, 1])

            # Legacy alias (backward compatibility)
            legacy_path = suite_dir / "analysis" / "qa_calibration_manifest.json"
            self.assertTrue(
                legacy_path.exists(),
                "Expected legacy qa_calibration_manifest.json alias",
            )

            # The sweep+finalize+reanalyze flow should call analyze() multiple times.
            # candidates=2, cases=2 => sweep analyze=4
            # finalize analyze=2
            # QA reanalyze=2
            self.assertEqual(len(pipeline.analyze_calls), 8)

    def test_qa_calibration_sweep_fails_if_any_sweep_candidate_has_analysis_errors(
        self,
    ) -> None:
        """If any gt_tolerance candidate sweep has non-zero analysis_rc, QA must FAIL."""

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            worktrees_root = self._make_minimal_worktrees_root(root)
            suite_root = root / "runs" / "suites"
            suite_id = "qa_sweep_analysis_rc_fail"

            args = self._make_args(
                suite_root=suite_root,
                worktrees_root=worktrees_root,
                suite_id=suite_id,
            )

            # Enable sweep + auto-selection with two candidates.
            args.gt_tolerance_sweep = "0,1"
            args.gt_tolerance_auto = True
            args.gt_tolerance_auto_min_fraction = 0.95

            # Simulate analyze() failures for one tolerance value during the sweep.
            pipeline = FakePipeline(nonempty_score=True, fail_on_gt_tolerance={1})

            buf = StringIO()
            with redirect_stdout(buf):
                rc = int(run_suite_mode(args, pipeline, repo_registry={}))

            self.assertNotEqual(rc, 0, f"Expected non-zero exit code. Output:\n{buf.getvalue()}")

            suite_dir = suite_root / safe_name(suite_id)

            checklist_path = suite_dir / "analysis" / "qa_calibration_checklist.txt"
            self.assertTrue(checklist_path.exists(), "Expected checklist file to be written")
            checklist = checklist_path.read_text(encoding="utf-8")
            self.assertIn("Overall: FAIL", checklist)
            self.assertIn("analysis_rc=0", checklist)

            # Sweep artifacts should still be written (the sweep report is useful for debugging).
            self.assertTrue(
                (suite_dir / "analysis" / "_tables" / "gt_tolerance_sweep_report.csv").exists()
            )
            self.assertTrue((suite_dir / "analysis" / "gt_tolerance_sweep.json").exists())

            # The sweep+finalize+reanalyze flow should still attempt all analyze() calls.
            self.assertEqual(len(pipeline.analyze_calls), 8)

    def test_qa_calibration_checklist_exposes_gt_ambiguity_warnings(self) -> None:
        """Ambiguous GT matches should be visible as WARN lines in the QA checklist (non-fatal)."""

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            worktrees_root = self._make_minimal_worktrees_root(root)
            suite_root = root / "runs" / "suites"
            suite_id = "qa_gt_ambiguity_warn"

            args = self._make_args(
                suite_root=suite_root,
                worktrees_root=worktrees_root,
                suite_id=suite_id,
            )

            # Enable sweep + auto-selection so selection warnings are produced and persisted.
            args.gt_tolerance_sweep = "0,1"
            args.gt_tolerance_auto = True
            args.gt_tolerance_auto_min_fraction = 0.95

            # Emit ambiguous overlaps in the per-case triage_features.csv.
            pipeline = FakePipeline(nonempty_score=True, ambiguous_gt=True)

            buf = StringIO()
            with redirect_stdout(buf):
                rc = int(run_suite_mode(args, pipeline, repo_registry={}))

            self.assertEqual(
                rc,
                0,
                f"Expected success (warnings are non-fatal). Output:\n{buf.getvalue()}",
            )

            suite_dir = suite_root / safe_name(suite_id)
            checklist_path = suite_dir / "analysis" / "qa_calibration_checklist.txt"
            self.assertTrue(checklist_path.exists(), "Expected checklist file to be written")
            checklist = checklist_path.read_text(encoding="utf-8")

            # Must still pass overall.
            self.assertIn("Overall: PASS", checklist)

            # Checklist should surface ambiguity counts.
            self.assertIn("GT ambiguity warnings (many-to-one / one-to-many", checklist)
            self.assertIn("many_to_one_clusters=", checklist)
            self.assertIn("one_to_many_gt_ids=", checklist)

            # Checklist should surface selection warnings (from selection JSON).
            self.assertIn("gt_tolerance_selection warnings", checklist)
            self.assertIn("clusters overlapping multiple GT IDs", checklist)


if __name__ == "__main__":
    unittest.main()
