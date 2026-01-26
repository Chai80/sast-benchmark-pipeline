import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

# These strings are the canonical, suite-relative artifact paths used throughout
# Layer 1 QA hardening. Docs should mention them so humans and CI know where to look.
REQUIRED_PATH_STRINGS = [
    # QA runbook outputs
    "analysis/qa_manifest.json",
    "analysis/qa_calibration_checklist.txt",
    # Suite-level triage calibration
    "analysis/_tables/triage_dataset.csv",
    "analysis/triage_calibration.json",
    "analysis/_tables/triage_calibration_report.csv",
    "analysis/_tables/triage_eval_summary.json",
    # Optional GT tolerance sweep/auto-selection outputs
    "analysis/_tables/gt_tolerance_sweep_report.csv",
    "analysis/_tables/gt_tolerance_sweep_tool_stats.csv",
    "analysis/gt_tolerance_sweep.json",
    "analysis/gt_tolerance_selection.json",
    "analysis/_sweeps/gt_tol_<t>/analysis/...",
]

# Paths we intentionally do NOT want docs to claim (historical drift). Keeping
# this small avoids over-constraining docs.
FORBIDDEN_PATH_STRINGS = [
    "analysis/gt_tolerance_sweep_report.csv",  # report lives under analysis/_tables/
]


class TestDocsArtifactPaths(unittest.TestCase):
    def test_docs_mention_canonical_artifact_paths(self) -> None:
        doc_files = [
            REPO_ROOT / "README.md",
            REPO_ROOT / "ARCHITECTURE.md",
            REPO_ROOT / "GeneralSystemArchitecture.md",
            REPO_ROOT / "docs" / "SYSTEM_DIAGRAMS.md",
            REPO_ROOT / "docs" / "triage_calibration.md",
        ]

        corpus_parts = []
        missing_files = []
        for p in doc_files:
            if not p.exists():
                missing_files.append(str(p.relative_to(REPO_ROOT)))
                continue
            corpus_parts.append(p.read_text(encoding="utf-8", errors="ignore"))

        if missing_files:
            self.fail(f"Expected documentation files missing from repo: {missing_files}")

        corpus = "\n\n".join(corpus_parts)

        missing = [s for s in REQUIRED_PATH_STRINGS if s not in corpus]
        if missing:
            self.fail(
                "Docs are missing canonical artifact paths (docs drift risk):\n"
                + "\n".join(f"- {m}" for m in missing)
            )

    def test_docs_do_not_claim_outdated_paths(self) -> None:
        # This is intentionally light-touch: we only ban a small number of
        # historically confusing paths.
        doc_files = [
            REPO_ROOT / "README.md",
            REPO_ROOT / "ARCHITECTURE.md",
            REPO_ROOT / "GeneralSystemArchitecture.md",
            REPO_ROOT / "docs" / "SYSTEM_DIAGRAMS.md",
            REPO_ROOT / "docs" / "triage_calibration.md",
        ]
        corpus = "\n\n".join(
            p.read_text(encoding="utf-8", errors="ignore") for p in doc_files if p.exists()
        )

        bad = [s for s in FORBIDDEN_PATH_STRINGS if s in corpus]
        if bad:
            self.fail(
                "Docs mention outdated/confusing artifact paths (please update docs):\n"
                + "\n".join(f"- {b}" for b in bad)
            )
