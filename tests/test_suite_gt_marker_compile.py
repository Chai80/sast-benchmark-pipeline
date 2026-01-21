import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = REPO_ROOT / "sast_cli.py"


class TestSuiteGTMarkerCompilation(unittest.TestCase):
    def test_compiles_gt_catalog_from_in_repo_markers_when_yaml_missing(self) -> None:
        """If benchmark/gt_catalog.yaml is absent, suite case prep should still
        produce <case_dir>/gt/gt_catalog.yaml by compiling in-repo markers.

        This keeps analysis one-directional: it reads canonical artifacts from
        the suite layout instead of re-opening the source repo.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            worktrees_root = root / "worktrees"
            worktrees_root.mkdir(parents=True, exist_ok=True)

            # Minimal "git checkout" marker.
            repo_dir = worktrees_root / "case-one"
            repo_dir.mkdir(parents=True, exist_ok=True)
            (repo_dir / ".git").mkdir()

            # No benchmark/gt_catalog.yaml on purpose.
            app_dir = repo_dir / "app"
            app_dir.mkdir(parents=True, exist_ok=True)

            # Marker-based GT (calibration suite style)
            (app_dir / "vuln.py").write_text(
                "\n".join(
                    [
                        "# DURINN_GT id=test_marker_1 track=sast set=core owasp=A01",
                        "def f():",
                        "    return 1",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

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

            result = subprocess.run(cmd, cwd=str(REPO_ROOT), text=True, capture_output=True)

            if result.returncode != 0:
                raise AssertionError(
                    "CLI returned non-zero exit code\n"
                    f"cmd: {' '.join(cmd)}\n"
                    f"stdout:\n{result.stdout}\n"
                    f"stderr:\n{result.stderr}\n"
                )

            gt_dir = suite_root / suite_id / "cases" / "case-one" / "gt"
            self.assertTrue(gt_dir.exists(), "Expected <case_dir>/gt/ directory")
            self.assertTrue((gt_dir / "gt_catalog.yaml").exists(), "Expected compiled gt_catalog.yaml")

            # The compiled catalog should include our marker id.
            yaml_text = (gt_dir / "gt_catalog.yaml").read_text(encoding="utf-8")
            self.assertIn("test_marker_1", yaml_text)
            self.assertIn("items:", yaml_text)


if __name__ == "__main__":
    unittest.main()
