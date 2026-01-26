import copy
import unittest


from pipeline.analysis.stages.triage import (
    TRIAGE_QUEUE_FIELDNAMES,
    TRIAGE_QUEUE_SCHEMA_VERSION,
    rank_triage_rows,
)


class TestTriageQueueContract(unittest.TestCase):
    def test_schema_contract_exists_and_is_sane(self) -> None:
        self.assertIsInstance(TRIAGE_QUEUE_SCHEMA_VERSION, str)
        self.assertTrue(TRIAGE_QUEUE_SCHEMA_VERSION.strip())

        self.assertIsInstance(TRIAGE_QUEUE_FIELDNAMES, list)
        self.assertGreaterEqual(len(TRIAGE_QUEUE_FIELDNAMES), 8)
        self.assertTrue(all(isinstance(x, str) and x.strip() for x in TRIAGE_QUEUE_FIELDNAMES))
        self.assertEqual(len(TRIAGE_QUEUE_FIELDNAMES), len(set(TRIAGE_QUEUE_FIELDNAMES)))

        # Required columns
        for required in [
            "triage_score_v1",
            "tool_count",
            "max_severity",
            "file_path",
            "start_line",
            "cluster_id",
        ]:
            self.assertIn(required, TRIAGE_QUEUE_FIELDNAMES)

    def test_sorting_is_deterministic_and_uses_cluster_id_baseline(self) -> None:
        base = {
            "triage_score_v1": "",
            "file_path": "a.py",
            "start_line": 1,
            "end_line": 1,
            "tool_count": 2,
            "total_findings": 5,
            "max_severity": "HIGH",
            "sample_rule_id": "R",
            "sample_title": "T",
            "_sev_rank": 3,
        }

        r1 = dict(base)
        r1["cluster_id"] = "a.py:1-1"
        r2 = dict(base)
        r2["cluster_id"] = "a.py:1-2"

        rows_a = [copy.deepcopy(r2), copy.deepcopy(r1)]
        rows_b = [copy.deepcopy(r1), copy.deepcopy(r2)]

        rank_triage_rows(rows_a, calibrated=False)
        rank_triage_rows(rows_b, calibrated=False)

        self.assertEqual([r["cluster_id"] for r in rows_a], [r["cluster_id"] for r in rows_b])
        self.assertEqual([r["cluster_id"] for r in rows_a], ["a.py:1-1", "a.py:1-2"])
        self.assertEqual([r["rank"] for r in rows_a], [1, 2])

    def test_calibrated_primary_score_then_fallback(self) -> None:
        base = {
            "file_path": "a.py",
            "start_line": 1,
            "end_line": 1,
            "tool_count": 1,
            "total_findings": 1,
            "max_severity": "LOW",
            "sample_rule_id": "R",
            "sample_title": "T",
            "_sev_rank": 1,
        }

        # Higher score should win even if severity is lower.
        hi = dict(base)
        hi.update({"triage_score_v1": 0.9, "cluster_id": "a.py:1-1"})
        lo = dict(base)
        lo.update({"triage_score_v1": 0.1, "cluster_id": "a.py:1-2"})
        rows = [lo, hi]
        rank_triage_rows(rows, calibrated=True)
        self.assertEqual([r["cluster_id"] for r in rows], ["a.py:1-1", "a.py:1-2"])

        # When scores tie, fall back to baseline severity ordering.
        s1 = dict(base)
        s1.update(
            {
                "triage_score_v1": 0.5,
                "cluster_id": "a.py:1-1",
                "_sev_rank": 3,
                "max_severity": "HIGH",
            }
        )
        s2 = dict(base)
        s2.update(
            {
                "triage_score_v1": 0.5,
                "cluster_id": "a.py:1-2",
                "_sev_rank": 1,
                "max_severity": "LOW",
            }
        )
        rows2 = [s2, s1]
        rank_triage_rows(rows2, calibrated=True)
        self.assertEqual([r["cluster_id"] for r in rows2], ["a.py:1-1", "a.py:1-2"])


if __name__ == "__main__":
    unittest.main()
