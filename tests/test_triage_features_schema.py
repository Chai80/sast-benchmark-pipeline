import unittest


from pipeline.analysis.stages.triage_features import TRIAGE_FEATURES_FIELDNAMES, TRIAGE_FEATURES_SCHEMA_VERSION


class TestTriageFeaturesSchema(unittest.TestCase):
    def test_schema_contract_exists_and_is_sane(self) -> None:
        # Schema version should be a non-empty, stable-ish identifier.
        self.assertIsInstance(TRIAGE_FEATURES_SCHEMA_VERSION, str)
        self.assertTrue(TRIAGE_FEATURES_SCHEMA_VERSION.strip())

        # Fieldnames should be a non-empty list of strings.
        self.assertIsInstance(TRIAGE_FEATURES_FIELDNAMES, list)
        self.assertGreater(len(TRIAGE_FEATURES_FIELDNAMES), 10)
        self.assertTrue(all(isinstance(x, str) and x.strip() for x in TRIAGE_FEATURES_FIELDNAMES))

        # No duplicates (duplicates can silently clobber columns in DictWriter).
        self.assertEqual(len(TRIAGE_FEATURES_FIELDNAMES), len(set(TRIAGE_FEATURES_FIELDNAMES)))

        # Stable IDs should be first and always present.
        self.assertEqual(TRIAGE_FEATURES_FIELDNAMES[0:3], ["suite_id", "case_id", "cluster_id"])

        # Canonical list-typed columns should be JSON-encoded.
        for required in [
            "tools_json",
            "tool_counts_json",
            "case_tags_json",
            "gt_overlap_ids_json",
            "gt_overlap_sets_json",
            "gt_overlap_tracks_json",
        ]:
            self.assertIn(required, TRIAGE_FEATURES_FIELDNAMES)

        # Must include labels.
        for required in ["gt_overlap", "gt_overlap_count"]:
            self.assertIn(required, TRIAGE_FEATURES_FIELDNAMES)


if __name__ == "__main__":
    unittest.main()
