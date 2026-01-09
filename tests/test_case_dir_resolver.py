import tempfile
import unittest
from pathlib import Path


from pipeline.layout import resolve_case_dir


class TestCaseDirResolver(unittest.TestCase):
    def test_resolve_case_dir_normalizes_underscore_vs_hyphen(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            suite_root = root / "runs" / "suites"
            suite_id = "20260101T000000Z"

            cases_dir = suite_root / suite_id / "cases"
            (cases_dir / "juice_shop").mkdir(parents=True, exist_ok=True)

            resolved = resolve_case_dir(
                case_id="juice-shop",
                suite_id=suite_id,
                suite_root=suite_root,
            )

            self.assertTrue(resolved.exists())
            self.assertEqual(resolved.name, "juice_shop")

    def test_resolve_case_dir_supports_latest_suite_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            suite_root = root / "runs" / "suites"
            suite_id = "20260102T000000Z"

            cases_dir = suite_root / suite_id / "cases"
            (cases_dir / "webgoat").mkdir(parents=True, exist_ok=True)
            (suite_root / "LATEST").parent.mkdir(parents=True, exist_ok=True)
            (suite_root / "LATEST").write_text(suite_id + "\n", encoding="utf-8")

            resolved = resolve_case_dir(
                case_id="webgoat",
                suite_id="latest",
                suite_root=suite_root,
            )

            self.assertTrue(resolved.exists())
            self.assertEqual(resolved.name, "webgoat")

    def test_resolve_case_dir_error_lists_valid_case_ids(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            suite_root = root / "runs" / "suites"
            suite_id = "20260103T000000Z"

            cases_dir = suite_root / suite_id / "cases"
            (cases_dir / "a_b").mkdir(parents=True, exist_ok=True)
            (cases_dir / "c-d").mkdir(parents=True, exist_ok=True)

            with self.assertRaises(FileNotFoundError) as ctx:
                resolve_case_dir(
                    case_id="does-not-exist",
                    suite_id=suite_id,
                    suite_root=suite_root,
                )

            msg = str(ctx.exception)
            self.assertIn("Valid case IDs", msg)
            self.assertIn("a_b", msg)
            self.assertIn("c-d", msg)


if __name__ == "__main__":
    unittest.main()
