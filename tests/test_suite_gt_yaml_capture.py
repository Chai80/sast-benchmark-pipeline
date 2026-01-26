import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = REPO_ROOT / "sast_cli.py"


class TestSuiteGTYAMLCapture(unittest.TestCase):
    def test_copies_canonical_benchmark_yaml_into_case_gt_dir(self) -> None:
        """Suite case prep should copy benchmark/gt_catalog.yaml into <case_dir>/gt.

        This is a deterministic ingest step (no filename discovery). The pipeline
        should ignore alternate extensions like *.yml.
        """

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            worktrees_root = root / "worktrees"
            worktrees_root.mkdir(parents=True, exist_ok=True)

            # Minimal "git checkout" marker.
            repo_dir = worktrees_root / "case-one"
            repo_dir.mkdir(parents=True, exist_ok=True)
            (repo_dir / ".git").mkdir()

            bench = repo_dir / "benchmark"
            bench.mkdir(parents=True, exist_ok=True)

            gt_yaml = "items:\n  - id: demo_1\n    file: src/app.js\n    line: 1\n"
            suite_sets_yaml = "sets:\n  core: [demo_1]\n"

            (bench / "gt_catalog.yaml").write_text(gt_yaml, encoding="utf-8")
            (bench / "suite_sets.yaml").write_text(suite_sets_yaml, encoding="utf-8")

            # Add alternate extensions that MUST NOT be copied.
            (bench / "gt_catalog.yml").write_text("items: []\n", encoding="utf-8")
            (bench / "suite_sets.yml").write_text("sets: {}\n", encoding="utf-8")

            suite_root = root / "runs" / "suites"
            suite_id = "20260101T000000Z"

            cmd = [
                sys.executable,
                str(CLI),
                "--mode",
                "suite",
                "--worktrees-root",
                str(worktrees_root),
                "--scanners",
                "semgrep",
                "--skip-analysis",
                "--dry-run",
                "--suite-root",
                str(suite_root),
                "--suite-id",
                suite_id,
            ]

            result = subprocess.run(
                cmd,
                cwd=str(REPO_ROOT),
                text=True,
                capture_output=True,
            )

            if result.returncode != 0:
                raise AssertionError(
                    "CLI returned non-zero exit code\n"
                    f"cmd: {' '.join(cmd)}\n"
                    f"stdout:\n{result.stdout}\n"
                    f"stderr:\n{result.stderr}\n"
                )

            gt_dir = suite_root / suite_id / "cases" / "case-one" / "gt"
            self.assertTrue(gt_dir.exists(), "Expected <case_dir>/gt/ directory")

            # Canonical files should be copied.
            self.assertEqual(gt_yaml, (gt_dir / "gt_catalog.yaml").read_text(encoding="utf-8"))
            self.assertEqual(
                suite_sets_yaml,
                (gt_dir / "suite_sets.yaml").read_text(encoding="utf-8"),
            )

            # Alternate extensions should NOT be copied.
            self.assertFalse((gt_dir / "gt_catalog.yml").exists(), "Should not copy gt_catalog.yml")
            self.assertFalse((gt_dir / "suite_sets.yml").exists(), "Should not copy suite_sets.yml")


if __name__ == "__main__":
    unittest.main()
