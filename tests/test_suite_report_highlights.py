import json
import tempfile
import unittest
from pathlib import Path

from pipeline.analysis.suite.suite_report import write_suite_report


class TestSuiteReportHighlights(unittest.TestCase):
    def test_suite_report_contains_results_highlights_block(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            suite_dir = Path(td) / "S1"
            (suite_dir / "cases").mkdir(parents=True, exist_ok=True)

            # Minimal suite.json
            (suite_dir / "suite.json").write_text(
                json.dumps(
                    {
                        "created_at": "2026-01-01T00:00:00Z",
                        "plan": {"scanners": ["semgrep", "snyk"]},
                        "cases": ["A01", "A02"],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            # Minimal suite-level artifacts referenced by the report
            tables_dir = suite_dir / "analysis" / "_tables"
            tables_dir.mkdir(parents=True, exist_ok=True)
            (tables_dir / "triage_dataset.csv").write_text(
                "suite_id,case_id\nS1,A01\n", encoding="utf-8"
            )
            (tables_dir / "triage_eval_summary.json").write_text("{}", encoding="utf-8")
            (tables_dir / "triage_eval_topk.csv").write_text(
                "case_id,strategy,rank,gt_overlap,gt_total,cumulative_gt_covered\n",
                encoding="utf-8",
            )
            (suite_dir / "analysis" / "triage_calibration.json").write_text(
                "{}", encoding="utf-8"
            )

            # QA artifacts (optional, but should show up in "where to click")
            (suite_dir / "analysis" / "qa_checklist.md").write_text(
                "# QA\n", encoding="utf-8"
            )
            (suite_dir / "analysis" / "qa_calibration_checklist.txt").write_text(
                "PASS\n", encoding="utf-8"
            )

            # Tolerance evidence (C3 integrity notes)
            (suite_dir / "analysis" / "gt_tolerance_sweep_summary.csv").write_text(
                "gt_tolerance,gt_tolerance_effective,tolerance_policy,clusters_total,gt_ids_covered,many_to_one_clusters,one_to_many_gt_ids,max_gt_ids_per_cluster,max_clusters_per_gt_id\n"
                "0,0,fixed,10,3,1,0,2,1\n",
                encoding="utf-8",
            )

            # Two cases with different gap_total and severities to make ordering deterministic.
            cases = [
                ("A01", 1, "LOW"),
                ("A02", 5, "HIGH"),
            ]
            for cid, gap_total, sev in cases:
                case_dir = suite_dir / "cases" / cid
                (case_dir / "analysis").mkdir(parents=True, exist_ok=True)
                (case_dir / "gt").mkdir(parents=True, exist_ok=True)

                # Create the referenced artifact files
                triage_csv = case_dir / "analysis" / "triage_queue.csv"
                triage_json = case_dir / "analysis" / "triage_queue.json"
                hotspot_pack = case_dir / "analysis" / "hotspot_drilldown_pack.json"
                triage_csv.write_text("rank\n1\n", encoding="utf-8")
                triage_json.write_text("{}", encoding="utf-8")
                hotspot_pack.write_text("{}", encoding="utf-8")

                (case_dir / "gt" / "gt_score.json").write_text("{}", encoding="utf-8")
                (case_dir / "gt" / "gt_gap_queue.csv").write_text(
                    "cluster_id\nc1\n", encoding="utf-8"
                )

                manifest = {
                    "context": {
                        "config": {"requested_tools": ["semgrep", "snyk"]},
                        "normalized_paths": {},
                    },
                    "stages": [
                        {"name": "location_matrix", "summary": {"clusters": 3}},
                        {
                            "name": "triage_queue",
                            "summary": {"rows": 7, "top_severity": sev},
                        },
                        {
                            "name": "gt_score",
                            "summary": {
                                "total_gt_items": 10,
                                "matched_gt_items": 2,
                                "match_rate": 0.2,
                                "gap_summary": {"gap_total": gap_total},
                            },
                        },
                    ],
                    "warnings": [],
                    "errors": [],
                    "artifacts": {
                        "triage_queue_csv": str(triage_csv),
                        "triage_queue_json": str(triage_json),
                        "hotspot_drilldown_pack": str(hotspot_pack),
                    },
                }

                (case_dir / "analysis" / "analysis_manifest.json").write_text(
                    json.dumps(manifest, indent=2) + "\n",
                    encoding="utf-8",
                )

            out = write_suite_report(suite_dir=suite_dir)

            md = Path(out["out_md"]).read_text(encoding="utf-8")
            self.assertIn("## Results highlights", md)
            self.assertIn("Top GT gap cases", md)
            # A02 should appear (largest gap_total)
            self.assertIn("`A02`", md)
            self.assertIn("Where to click", md)
            # C3: integrity notes should surface tolerance ambiguity when evidence is present
            self.assertIn("## Integrity notes", md)
            self.assertIn("many_to_one_clusters=1", md)
