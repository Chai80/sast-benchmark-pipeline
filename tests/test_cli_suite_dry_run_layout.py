import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = REPO_ROOT / "sast_cli.py"


class TestCLISuiteDryRunLayout(unittest.TestCase):
    def test_suite_mode_dry_run_writes_suite_layout(self) -> None:
        # Create a fake worktrees root with two minimal "git checkouts".
        # The suite loader only requires a `.git` entry to treat a directory as a checkout.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            worktrees_root = root / "worktrees"
            worktrees_root.mkdir(parents=True, exist_ok=True)

            for name in ["case-one", "case_two"]:
                repo_dir = worktrees_root / name
                repo_dir.mkdir(parents=True, exist_ok=True)
                (
                    repo_dir / ".git"
                ).mkdir()  # marker only; does not need to be a real git repo
                (repo_dir / "README.md").write_text("demo\n", encoding="utf-8")

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

            # Suite artifacts should exist even in dry-run mode (manifests are the source of truth).
            latest = suite_root / "LATEST"
            self.assertTrue(latest.exists(), "Expected LATEST pointer under suite_root")
            self.assertEqual(suite_id, latest.read_text(encoding="utf-8").strip())

            suite_dir = suite_root / suite_id
            self.assertTrue(
                (suite_dir / "suite.json").exists(),
                "suite.json should be written by resolver",
            )
            self.assertTrue(
                (suite_dir / "summary.csv").exists(),
                "summary.csv should be written best-effort",
            )

            # Case artifacts should exist for each discovered checkout
            for case_id in ["case-one", "case_two"]:
                case_dir = suite_dir / "cases" / case_id
                case_json = case_dir / "case.json"
                self.assertTrue(
                    case_json.exists(), f"case.json should exist for {case_id}"
                )

                data = json.loads(case_json.read_text(encoding="utf-8"))
                # Basic invariants
                self.assertEqual(suite_id, (data.get("suite") or {}).get("id"))
                self.assertEqual(case_id, (data.get("case") or {}).get("id"))

                # Tool command should use module invocation (python -m tools.scan_semgrep)
                tool_runs = data.get("tool_runs") or {}
                semgrep = tool_runs.get("semgrep") or {}
                cmd_str = semgrep.get("command") or ""
                self.assertIn("-m tools.scan_semgrep", cmd_str)


if __name__ == "__main__":
    unittest.main()
