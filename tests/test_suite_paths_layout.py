import json
import tempfile
import unittest
from pathlib import Path

from pipeline.suites.layout import SuitePaths, ensure_suite_dirs, get_suite_paths, write_latest_suite_pointer


class TestSuitePathsLayout(unittest.TestCase):
    def test_get_suite_paths_returns_suite_named_dataclass(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            suite_root = Path(td) / "runs" / "suites"

            paths = get_suite_paths(case_id="juice shop", suite_id="test suite", suite_root=suite_root)

            self.assertIsInstance(paths, SuitePaths)

            # IDs are sanitized for folder safety
            self.assertEqual(paths.suite_id, "test_suite")
            self.assertEqual(paths.case_id, "juice_shop")

            # The directory names match the sanitized IDs
            self.assertEqual(paths.suite_dir.name, paths.suite_id)
            self.assertEqual(paths.case_dir.name, paths.case_id)

            # Bundle terminology should not leak through the public suite paths object
            self.assertFalse(hasattr(paths, "bundle_id"))
            self.assertFalse(hasattr(paths, "target"))

            ensure_suite_dirs(paths)
            self.assertTrue(paths.suite_json_path.exists())

            suite_json = json.loads(paths.suite_json_path.read_text(encoding="utf-8"))
            self.assertEqual(suite_json.get("suite_id"), paths.suite_id)

            write_latest_suite_pointer(paths)
            latest_path = suite_root / "LATEST"
            self.assertTrue(latest_path.exists())
            self.assertEqual(latest_path.read_text(encoding="utf-8").strip(), paths.suite_id)
