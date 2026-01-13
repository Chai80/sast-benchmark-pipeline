import csv
import json
import tempfile
import unittest
from pathlib import Path


from pipeline.suites.layout import ensure_suite_dirs, get_suite_paths
from pipeline.suites.manifests import (
    append_summary_row,
    update_latest_pointer,
    update_suite_artifacts,
    write_case_manifest,
    write_suite_manifest,
)


class TestSuiteManifestWriters(unittest.TestCase):
    def test_case_manifest_and_suite_indexes_are_written(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            paths = get_suite_paths(case_id="case1", suite_id="S1", suite_root=root)
            ensure_suite_dirs(paths)
            update_latest_pointer(paths)

            # Pre-analysis manifest
            warnings = ["warn1"]
            manifest = write_case_manifest(
                paths=paths,
                invocation_mode="benchmark",
                argv=["python", "sast_cli.py"],
                python_executable="python",
                skip_analysis=True,
                repo_label="example",
                repo_url="https://example.invalid/repo.git",
                repo_path=str(root / "repo"),
                runs_repo_name="example_repo",
                expected_branch="main",
                expected_commit=None,
                track="sast",
                tags={"track": "sast"},
                git_branch="main",
                git_commit="deadbeef",
                started="2026-01-01T00:00:00Z",
                finished=None,
                scanners_requested=["semgrep"],
                scanners_used=["semgrep"],
                tool_runs={"semgrep": {"exit_code": 0}},
                analysis=None,
                warnings=warnings,
                errors=[],
            )

            self.assertTrue(paths.case_json_path.exists())
            loaded = json.loads(paths.case_json_path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["case"]["id"], "case1")
            self.assertEqual(loaded["suite"]["id"], "S1")
            self.assertIn("environment", loaded["invocation"])

            # Suite-level artifacts
            write_suite_manifest(paths, manifest)
            append_summary_row(paths)

            self.assertTrue(paths.suite_json_path.exists())
            suite_data = json.loads(paths.suite_json_path.read_text(encoding="utf-8"))
            self.assertIn("cases", suite_data)
            self.assertIn("case1", suite_data["cases"])

            self.assertTrue(paths.suite_summary_path.exists())
            with paths.suite_summary_path.open("r", newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertTrue(any(r.get("case") == "case1" for r in rows))

            # Convenience wrapper should be safe/idempotent
            update_suite_artifacts(paths, manifest)


if __name__ == "__main__":
    unittest.main()
