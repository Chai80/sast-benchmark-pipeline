from __future__ import annotations

"""pipeline.analysis.suite.triage_eval.model

Small dataclasses used by the suite triage-eval builder.

Rationale
---------
``build_triage_eval`` is intentionally a thin orchestrator, but it still needs
to pass around a handful of related values (suite id, K list, output paths,
etc.). These dataclasses provide a stable "shape" for that state so follow-up
refactors can decompose stages without exploding parameter lists.

Notes
-----
These structures are *scaffolding* for future refactors; they are not intended
to change behavior.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence


@dataclass(frozen=True)
class TriageEvalBuildRequest:
    """User-facing inputs to :func:`build_triage_eval`."""

    suite_dir: Path
    suite_id: Optional[str] = None
    ks: Sequence[int] = (1, 3, 5, 10, 25, 50)
    out_dirname: str = "analysis"
    include_tool_marginal: bool = True
    dataset_relpath: str = "analysis/_tables/triage_dataset.csv"

    @property
    def suite_dir_resolved(self) -> Path:
        return Path(self.suite_dir).resolve()

    @property
    def suite_id_effective(self) -> str:
        sd = self.suite_dir_resolved
        return str(self.suite_id) if self.suite_id else sd.name


@dataclass(frozen=True)
class TriageEvalPaths:
    """Resolved output paths for triage-eval artifacts."""

    out_dir: Path
    out_tables: Path

    out_by_case_csv: Path
    out_summary_json: Path
    out_tool_csv: Path
    out_tool_marginal_csv: Path
    out_topk_csv: Path
    out_deltas_by_case_csv: Path
    out_log: Path

    @classmethod
    def for_suite(cls, *, suite_dir: Path, out_dirname: str) -> "TriageEvalPaths":
        suite_dir = Path(suite_dir).resolve()
        out_dir = (suite_dir / out_dirname).resolve()
        out_tables = (out_dir / "_tables").resolve()

        return cls(
            out_dir=out_dir,
            out_tables=out_tables,
            out_by_case_csv=(out_tables / "triage_eval_by_case.csv"),
            out_summary_json=(out_tables / "triage_eval_summary.json"),
            out_tool_csv=(out_tables / "triage_tool_utility.csv"),
            out_tool_marginal_csv=(out_tables / "triage_tool_marginal.csv"),
            out_topk_csv=(out_tables / "triage_eval_topk.csv"),
            out_deltas_by_case_csv=(out_tables / "triage_eval_deltas_by_case.csv"),
            out_log=(out_tables / "triage_eval.log"),
        )
