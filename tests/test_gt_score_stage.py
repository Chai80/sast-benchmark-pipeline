import json
import tempfile
import unittest
from pathlib import Path


from pipeline.analysis.framework.context import AnalysisContext
from pipeline.analysis.framework.store import ArtifactStore
from pipeline.analysis.stages.gt_score import stage_gt_score


class TestGTScoreStage(unittest.TestCase):
    def _write_case_json(
        self, case_dir: Path, *, repo_path: Path, track: str | None
    ) -> None:
        payload = {
            "case": {
                "id": "demo",
                "track": track,
            },
            "repo": {
                "repo_path": str(repo_path),
            },
        }
        (case_dir / "case.json").write_text(json.dumps(payload), encoding="utf-8")

    def _write_normalized(self, norm_path: Path, *, file_path: str, line: int) -> None:
        payload = {
            "findings": [
                {
                    "finding_id": "1",
                    "tool": "semgrep",
                    "file_path": file_path,
                    "line_number": line,
                    "end_line_number": line,
                    "rule_id": "TST",
                    "title": "Test",
                }
            ]
        }
        norm_path.write_text(json.dumps(payload), encoding="utf-8")

    def test_scores_marker_hit_when_track_matches(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo_dir = root / "repo"
            repo_dir.mkdir()
            (repo_dir / "src").mkdir()
            marker_path = repo_dir / "src" / "app.js"
            marker_path.write_text(
                "// DURINN_GT id=demo_1 track=sast set=core\nconsole.log('x');\n",
                encoding="utf-8",
            )
            marker_line = 1

            case_dir = root / "case"
            (case_dir / "analysis").mkdir(parents=True)
            (case_dir / "tool_runs" / "semgrep" / "2026010101000000").mkdir(parents=True)

            norm_path = case_dir / "tool_runs" / "semgrep" / "2026010101000000" / "normalized.json"
            self._write_normalized(norm_path, file_path="src/app.js", line=marker_line)

            self._write_case_json(case_dir, repo_path=repo_dir, track="sast")

            ctx = AnalysisContext.build(
                repo_name="juice-shop",
                tools=["semgrep"],
                runs_dir=case_dir / "tool_runs",
                out_dir=case_dir / "analysis",
                mode="security",
                tolerance=0,
                normalized_paths={"semgrep": norm_path},
            )
            store = ArtifactStore()

            summary = stage_gt_score(ctx, store)
            self.assertEqual("ok", summary.get("status"))
            self.assertEqual("sast", summary.get("scoring_track"))
            self.assertEqual(1, summary.get("matched_gt_items"))
            self.assertEqual(1, summary.get("total_gt_items"))

    def test_skips_when_case_track_filters_out_all_gt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo_dir = root / "repo"
            repo_dir.mkdir()
            (repo_dir / "main.py").write_text(
                "# DURINN_GT id=demo_1 track=sast set=core\nprint('x')\n",
                encoding="utf-8",
            )

            case_dir = root / "case"
            (case_dir / "analysis").mkdir(parents=True)
            (case_dir / "tool_runs" / "semgrep" / "2026010101000000").mkdir(parents=True)

            norm_path = case_dir / "tool_runs" / "semgrep" / "2026010101000000" / "normalized.json"
            self._write_normalized(norm_path, file_path="main.py", line=1)

            # Track does *not* match marker track.
            self._write_case_json(case_dir, repo_path=repo_dir, track="iac")

            ctx = AnalysisContext.build(
                repo_name="repo",
                tools=["semgrep"],
                runs_dir=case_dir / "tool_runs",
                out_dir=case_dir / "analysis",
                mode="security",
                tolerance=0,
                normalized_paths={"semgrep": norm_path},
            )
            store = ArtifactStore()

            summary = stage_gt_score(ctx, store)
            self.assertEqual("skipped", summary.get("status"))
            self.assertEqual("no_gt_for_track", summary.get("reason"))
            self.assertEqual("iac", summary.get("track"))


if __name__ == "__main__":
    unittest.main()
