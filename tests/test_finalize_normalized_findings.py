import unittest


from tools.core import finalize_normalized_findings


class TestFinalizeNormalizedFindings(unittest.TestCase):
    def test_sorts_findings_and_set_like_fields(self) -> None:
        findings = [
            {
                "finding_id": "b",
                "file_path": "b.py",
                "line_number": 2,
                "end_line_number": 2,
                "rule_id": "R2",
                "title": "B",
                "cwe_ids": ["79", "22"],
                "owasp_top_10_2021": {"codes": ["A03", "A01"], "categories": ["X", "A"]},
            },
            {
                "finding_id": "a",
                "file_path": "a.py",
                "line_number": 10,
                "end_line_number": 12,
                "rule_id": "R1",
                "title": "A",
                "cwe_ids": ["200", "79"],
                "owasp_top_10_2021": {"codes": ["A02"], "categories": ["B"]},
            },
        ]

        out = finalize_normalized_findings(findings)

        # Sort by file then line
        self.assertEqual(["a.py", "b.py"], [out[0]["file_path"], out[1]["file_path"]])

        # cwe_ids are treated as set-like and sorted
        self.assertEqual(["200", "79"], out[0]["cwe_ids"])
        self.assertEqual(["22", "79"], out[1]["cwe_ids"])

        # OWASP blocks are stabilized too
        self.assertEqual(["A01", "A03"], out[1]["owasp_top_10_2021"]["codes"])
        self.assertEqual(["A", "X"], out[1]["owasp_top_10_2021"]["categories"])


if __name__ == "__main__":
    unittest.main()
