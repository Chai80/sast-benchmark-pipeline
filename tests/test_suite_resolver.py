import json
import tempfile
import unittest
from pathlib import Path


from pipeline.models import CaseSpec, RepoSpec
from pipeline.suites.suite_definition import SuiteAnalysisDefaults, SuiteCase, SuiteDefinition
from pipeline.suites.suite_resolver import SuiteInputProvenance, resolve_suite_run


class TestSuiteResolver(unittest.TestCase):
    def test_resolver_writes_suite_json_plan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            suite_root = root / "runs" / "suites"

            # Local repo path doesn't need to exist for resolver; it's only recorded.
            local_repo = root / "repos" / "example"

            suite_def = SuiteDefinition(
                suite_id="example_workload",
                scanners=["semgrep"],
                cases=[
                    SuiteCase(
                        case=CaseSpec(
                            case_id="Case 1",
                            runs_repo_name="example",
                            label="Example",
                            repo=RepoSpec(repo_path=str(local_repo)),
                        )
                    )
                ],
                analysis=SuiteAnalysisDefaults(skip=False, tolerance=3, filter="security"),
            )

            resolved = resolve_suite_run(
                suite_def=suite_def,
                suite_id="20260101T000000Z",
                suite_root=suite_root,
                scanners=["semgrep"],
                analysis=suite_def.analysis,
                provenance=SuiteInputProvenance(built_interactively=True),
                repo_registry=None,
                ensure_dirs=True,
            )

            suite_json_path = resolved.suite_dir / "suite.json"
            self.assertTrue(suite_json_path.exists())

            data = json.loads(suite_json_path.read_text(encoding="utf-8"))
            self.assertEqual(data.get("suite_id"), resolved.suite_id)
            self.assertIn("plan", data)
            self.assertIsInstance(data["plan"], dict)
            self.assertEqual(data["plan"].get("scanners"), ["semgrep"])

            plan_cases = data["plan"].get("cases")
            self.assertIsInstance(plan_cases, list)
            self.assertEqual(len(plan_cases), 1)
            self.assertEqual(plan_cases[0].get("case_id"), resolved.cases[0].suite_case.case.case_id)

            # Execution summary starts empty; it will be filled by orchestrator during runs.
            self.assertEqual(data.get("cases"), {})

    def test_resolver_supports_repo_key_via_registry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            suite_root = root / "runs" / "suites"

            suite_def = SuiteDefinition(
                suite_id="registry_workload",
                scanners=["semgrep"],
                cases=[
                    SuiteCase(
                        case=CaseSpec(
                            case_id="juice",
                            runs_repo_name="juice",
                            label="Juice",
                            repo=RepoSpec(repo_key="juice_shop"),
                        )
                    )
                ],
                analysis=SuiteAnalysisDefaults(),
            )

            registry = {
                "juice_shop": {
                    "label": "Juice Shop",
                    "repo_url": "https://github.com/juice-shop/juice-shop.git",
                }
            }

            resolved = resolve_suite_run(
                suite_def=suite_def,
                suite_id="20260101T000001Z",
                suite_root=suite_root,
                scanners=["semgrep"],
                analysis=suite_def.analysis,
                provenance=SuiteInputProvenance(suite_file="suite_input.py"),
                repo_registry=registry,
                ensure_dirs=False,
            )

            self.assertEqual(len(resolved.cases), 1)
            case = resolved.cases[0].suite_case.case
            self.assertEqual(case.repo.repo_key, "juice_shop")
            self.assertEqual(case.repo.repo_url, registry["juice_shop"]["repo_url"])


if __name__ == "__main__":
    unittest.main()
