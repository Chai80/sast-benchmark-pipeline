"""cli.commands.suite.runbook_steps.qa

Post-run suite aggregation and QA calibration steps.

This module keeps the heavyweight, filesystem-first aggregation logic out of
``cli.commands.suite.runbook`` so the runbook reads as a simple sequence of
steps.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from pipeline.orchestrator import AnalyzeRequest
from pipeline.suites.bundles import safe_name
from pipeline.suites.suite_resolver import ResolvedSuiteRun

from ..gt_tolerance_runbook import run_gt_tolerance_policy_runbook
from .model import SuiteRunContext


@dataclass(frozen=True)
class QARunbookContext:
    """Derived context for the QA calibration portion of the suite runbook.

    This is intentionally small scaffolding so the QA runbook stage can be
    decomposed into explicit steps without exploding parameter lists.
    """

    suite_id: str
    suite_root: Path
    suite_dir: Path
    scanners: List[str]
    tolerance: int
    analysis_filter: str


def build_suite_artifacts(ctx: SuiteRunContext, resolved_run: ResolvedSuiteRun) -> int:
    """Build suite-level artifacts after running all cases.

    This is intentionally filesystem-first and best-effort. Most failures should
    not abort the suite run.

    Returns
    -------
    int
        Exit code contribution for artifact build steps.

        Today, this is primarily used for QA calibration runs where a requested
        GT tolerance sweep is treated as a first-class requirement.
    """

    args = ctx.args

    qa_mode = ctx.flags.qa_mode

    suite_id = resolved_run.suite_id
    suite_dir = resolved_run.suite_dir
    skip_analysis = bool(ctx.skip_analysis)

    if bool(args.dry_run) or skip_analysis:
        return 0

    stage_rc = 0

    # ------------------------------------------------------------------
    # Optional deterministic GT tolerance sweep + selection (QA calibration).
    # ------------------------------------------------------------------
    stage_rc = run_gt_tolerance_policy_runbook(ctx, resolved_run, overall=stage_rc)

    # ------------------------------------------------------------------
    # Suite-level aggregation: triage dataset + calibration (+ optional eval).
    # ------------------------------------------------------------------
    # From this point on, the rest of the runbook assumes the *effective*
    # gt_tolerance has been applied (either explicit or auto-selected).
    try:
        from pipeline.analysis.suite.suite_triage_dataset import build_triage_dataset

        ds = build_triage_dataset(suite_dir=suite_dir, suite_id=suite_id)

        print("\n📦 Suite triage_dataset")
        print(f"  Output : {ds.get('out_csv')}")
        print(f"  Rows   : {ds.get('rows')}")

        if ds.get("missing_cases"):
            missing = ds.get("missing_cases") or []
            print(f"  ⚠️  Missing triage_features.csv for {len(missing)} case(s): " + ", ".join([str(x) for x in missing]))

        if ds.get("empty_cases"):
            empty = ds.get("empty_cases") or []
            print(f"  ⚠️  Empty triage_features.csv for {len(empty)} case(s): " + ", ".join([str(x) for x in empty]))

        if ds.get("read_errors"):
            errs = ds.get("read_errors") or []
            print(
                f"  ⚠️  Failed to read triage_features.csv for {len(errs)} case(s). "
                "See triage_dataset_build.log under suite analysis."
            )

        if ds.get("schema_mismatch_cases"):
            mism = ds.get("schema_mismatch_cases") or []
            print(
                f"  ⚠️  Schema mismatch triage_features.csv for {len(mism)} case(s). "
                "See triage_dataset_build.log under suite analysis."
            )

    except Exception as e:
        print(f"\n⚠️  Failed to build suite triage_dataset: {e}")

    # Suite-level calibration: tool weights for triage tie-breaking.
    try:
        from pipeline.analysis.suite.suite_triage_calibration import build_triage_calibration

        cal = build_triage_calibration(suite_dir=suite_dir, suite_id=suite_id)

        print("\n🧭 Suite triage_calibration")
        print(f"  Output : {cal.get('out_json')}")
        print(f"  Tools  : {cal.get('tools')}")
        print(f"  Cases  : {len(cal.get('included_cases') or [])} (included w/ GT)")

        if cal.get("excluded_cases_no_gt"):
            ex = cal.get("excluded_cases_no_gt") or []
            print(f"  ⚠️  Excluded cases without GT: {len(ex)}")

        if cal.get("suspicious_cases"):
            sus = cal.get("suspicious_cases") or []
            print(f"  ⚠️  Suspicious cases (GT present but no overlaps): {len(sus)}")

    except Exception as e:
        print(f"\n⚠️  Failed to build suite triage_calibration: {e}")

    # Suite-level evaluation: triage ranking quality + tool utility.
    # In QA calibration mode, we evaluate after the re-analyze pass.
    if not qa_mode:
        try:
            from pipeline.analysis.suite.suite_triage_eval import build_triage_eval

            ev = build_triage_eval(suite_dir=suite_dir, suite_id=suite_id)

            print("\n📈 Suite triage_eval")
            print(f"  Summary : {ev.get('out_summary_json')}")
            print(f"  By-case : {ev.get('out_by_case_csv')}")
            print(f"  Tools   : {ev.get('out_tool_utility_csv')}")

            if ev.get("out_tool_marginal_csv"):
                print(f"  Marginal: {ev.get('out_tool_marginal_csv')}")

            # Print a compact macro snapshot for Ks that matter for triage.
            try:
                ks_list = ev.get("ks") or [1, 3, 5, 10, 25]
                for k in ks_list:
                    for strat in ["baseline", "agreement", "calibrated"]:
                        ks = ev.get("macro", {}).get(strat, {}).get(str(k))
                        if ks:
                            mp = ks.get("precision")
                            mc = ks.get("gt_coverage")
                            print(f"  {strat} macro@{k}: precision={mp} coverage={mc}")
            except Exception:
                pass
        except Exception as e:
            print(f"\n⚠️  Failed to build suite triage_eval: {e}")

    return int(stage_rc)


def post_run_aggregation_and_qa(ctx: SuiteRunContext, resolved_run: ResolvedSuiteRun, overall: int) -> int:
    """Suite-level aggregation + QA calibration runbook (best-effort)."""

    args = ctx.args

    qa_mode = ctx.flags.qa_mode

    suite_id = resolved_run.suite_id
    suite_root = resolved_run.suite_root
    suite_dir = resolved_run.suite_dir

    qa_ctx = QARunbookContext(
        suite_id=str(suite_id),
        suite_root=Path(suite_root),
        suite_dir=Path(suite_dir),
        scanners=list(ctx.scanners),
        tolerance=int(ctx.tolerance or 0),
        analysis_filter=str(ctx.analysis_filter or ""),
    )
    skip_analysis = bool(ctx.skip_analysis)

    overall = max(overall, build_suite_artifacts(ctx, resolved_run))

    # ------------------------------------------------------------------
    # QA calibration runbook: second pass analyze + deterministic checklist
    # ------------------------------------------------------------------
    if qa_mode and (not bool(args.dry_run)) and (not bool(skip_analysis)):
        overall = _run_qa_calibration_runbook(ctx, resolved_run, qa_ctx=qa_ctx, overall=int(overall))

    return int(overall)


def _run_qa_calibration_runbook(
    ctx: SuiteRunContext,
    resolved_run: ResolvedSuiteRun,
    *,
    qa_ctx: QARunbookContext,
    overall: int,
) -> int:
    """Run QA calibration stages (best-effort).

    Split out of :func:`post_run_aggregation_and_qa` so the runbook step is
    readable and individual stages can be refactored safely.
    """

    overall = _qa_stage_reanalyze(ctx, resolved_run, qa_ctx=qa_ctx, overall=int(overall))
    _qa_stage_build_triage_eval(ctx, qa_ctx=qa_ctx)

    checks, overall = _qa_stage_validate_suite(ctx, qa_ctx=qa_ctx, overall=int(overall))
    overall = _qa_stage_write_manifest(ctx, qa_ctx=qa_ctx, overall=int(overall))

    rep_paths = _qa_stage_write_suite_report(qa_ctx=qa_ctx)
    checks = _qa_stage_append_suite_report_checks(checks, qa_ctx=qa_ctx, rep_paths=rep_paths)

    overall = _qa_stage_write_checklist_artifacts(checks, qa_ctx=qa_ctx, overall=int(overall))

    return int(overall)


def _qa_stage_reanalyze(
    ctx: SuiteRunContext,
    resolved_run: ResolvedSuiteRun,
    *,
    qa_ctx: QARunbookContext,
    overall: int,
) -> int:
    """QA calibration re-analyze pass (optional)."""

    args = ctx.args
    qa_no_reanalyze = ctx.flags.qa_no_reanalyze

    if qa_no_reanalyze:
        print("\n🧪 QA calibration: skipping re-analyze pass (--qa-no-reanalyze).")
        return int(overall)

    print("\n🔁 QA calibration: re-analyzing cases to apply triage calibration")
    for j, rc2 in enumerate(resolved_run.cases, start=1):
        c2 = rc2.suite_case.case
        print("\n" + "-" * 72)
        print(f"🔁 Analyze {j}/{len(resolved_run.cases)}: {c2.case_id}")

        # Explicit case_path prevents case-id normalization surprises.
        case_dir = (qa_ctx.suite_dir / "cases" / safe_name(c2.case_id)).resolve()
        try:
            areq = AnalyzeRequest(
                metric="suite",
                case=c2,
                suite_root=qa_ctx.suite_root,
                suite_id=qa_ctx.suite_id,
                case_path=str(case_dir),
                tools=tuple(qa_ctx.scanners),
                tolerance=int(qa_ctx.tolerance),
                gt_tolerance=int(getattr(args, "gt_tolerance", 0)),
                gt_source=str(getattr(args, "gt_source", "auto")),
                analysis_filter=str(qa_ctx.analysis_filter),
                exclude_prefixes=getattr(args, "exclude_prefixes", ()) or (),
                include_harness=bool(getattr(args, "include_harness", False)),
                skip_suite_aggregate=True,
            )
            rc_code2 = int(ctx.pipeline.analyze(areq))
        except Exception as e:
            print(f"  ❌ re-analyze failed for {c2.case_id}: {e}")
            rc_code2 = 2

        overall = max(int(overall), int(rc_code2))

    return int(overall)


def _qa_stage_build_triage_eval(ctx: SuiteRunContext, *, qa_ctx: QARunbookContext) -> None:
    """Suite-level triage_eval stage (best-effort)."""

    try:
        from pipeline.analysis.suite.suite_triage_eval import build_triage_eval

        ev = build_triage_eval(suite_dir=qa_ctx.suite_dir, suite_id=qa_ctx.suite_id)

        print("\n📈 Suite triage_eval (QA)")
        print(f"  Summary : {ev.get('out_summary_json')}")
        print(f"  By-case : {ev.get('out_by_case_csv')}")
        print(f"  Tools   : {ev.get('out_tool_utility_csv')}")

        if ev.get("out_tool_marginal_csv"):
            print(f"  Marginal: {ev.get('out_tool_marginal_csv')}")
    except Exception as e:
        print(f"\n⚠️  Failed to build suite triage_eval (QA): {e}")


def _qa_stage_validate_suite(
    ctx: SuiteRunContext,
    *,
    qa_ctx: QARunbookContext,
    overall: int,
) -> tuple[List[Any], int]:
    """Validate suite artifacts (filesystem-first).

    Returns
    -------
    tuple
        (checks, overall)
    """

    checks: List[Any] = []
    try:
        from pipeline.analysis.qa.qa_calibration_runbook import (
            all_ok,
            validate_calibration_suite_artifacts,
        )

        checks = validate_calibration_suite_artifacts(
            suite_dir=qa_ctx.suite_dir,
            require_scored_queue=(not bool(ctx.flags.qa_no_reanalyze)),
            expect_calibration=True,
            expect_gt_tolerance_sweep=bool(ctx.gt_sweep.sweep_raw or ctx.gt_sweep.auto_enabled),
            expect_gt_tolerance_selection=True,
        )

        ctx.qa_checklist_pass = bool(all_ok(checks))
    except Exception as e:
        print(f"\n❌ QA calibration validation failed: {e}")
        overall = max(int(overall), 2)
        ctx.qa_checklist_pass = False
        checks = []

    if not bool(ctx.qa_checklist_pass):
        overall = max(int(overall), 2)

    return checks, int(overall)


def _qa_stage_write_manifest(ctx: SuiteRunContext, *, qa_ctx: QARunbookContext, overall: int) -> int:
    """Write QA manifest (best-effort).

    We write the manifest even when the checklist fails so CI can scrape it.
    """

    args = ctx.args
    try:
        from pipeline.analysis.qa.qa_calibration_manifest import (
            GTTolerancePolicyRecord,
            build_qa_calibration_manifest,
            write_qa_calibration_manifest,
        )

        suite_dir = qa_ctx.suite_dir

        artifacts = {
            "triage_dataset_csv": str((suite_dir / "analysis" / "_tables" / "triage_dataset.csv").resolve()),
            "triage_calibration_json": str((suite_dir / "analysis" / "triage_calibration.json").resolve()),
            "triage_eval_summary_json": str((suite_dir / "analysis" / "_tables" / "triage_eval_summary.json").resolve()),
            "suite_report_md": str((suite_dir / "analysis" / "suite_report.md").resolve()),
            "suite_report_json": str((suite_dir / "analysis" / "suite_report.json").resolve()),
            "triage_tool_utility_csv": str((suite_dir / "analysis" / "_tables" / "triage_tool_utility.csv").resolve()),
            "triage_tool_marginal_csv": str((suite_dir / "analysis" / "_tables" / "triage_tool_marginal.csv").resolve()),
            "qa_checklist_json": str((suite_dir / "analysis" / "qa_checklist.json").resolve()),
            "qa_checklist_md": str((suite_dir / "analysis" / "qa_checklist.md").resolve()),
            "qa_checklist_txt": str((suite_dir / "analysis" / "qa_calibration_checklist.txt").resolve()),
            "gt_tolerance_selection_json": ctx.gt_sweep.selection_path,
        }

        if ctx.gt_sweep.enabled:
            artifacts.update(
                {
                    "gt_tolerance_sweep_report_csv": ctx.gt_sweep.report_csv,
                    "gt_tolerance_sweep_payload_json": ctx.gt_sweep.payload_json,
                    "gt_tolerance_sweep_tool_stats_csv": str(
                        (suite_dir / "analysis" / "_tables" / "gt_tolerance_sweep_tool_stats.csv").resolve()
                    ),
                }
            )

        gt_policy = GTTolerancePolicyRecord(
            initial_gt_tolerance=int(ctx.gt_tolerance_initial),
            effective_gt_tolerance=int(getattr(args, "gt_tolerance", 0) or 0),
            sweep_enabled=bool(ctx.gt_sweep.enabled),
            sweep_candidates=[int(x) for x in (ctx.gt_sweep.candidates or [])],
            auto_enabled=bool(getattr(args, "gt_tolerance_auto", False)),
            auto_min_fraction=float(getattr(args, "gt_tolerance_auto_min_fraction", 0.95) or 0.95)
            if bool(getattr(args, "gt_tolerance_auto", False))
            else None,
            selection_path=ctx.gt_sweep.selection_path,
            sweep_report_csv=ctx.gt_sweep.report_csv,
            sweep_payload_json=ctx.gt_sweep.payload_json,
            selection_warnings=list(ctx.gt_sweep.selection_warnings or []),
        )

        manifest = build_qa_calibration_manifest(
            suite_id=str(qa_ctx.suite_id),
            suite_dir=suite_dir,
            argv=list(sys.argv),
            scanners=list(qa_ctx.scanners),
            tolerance=int(qa_ctx.tolerance),
            analysis_filter=str(qa_ctx.analysis_filter),
            gt_source=str(getattr(args, "gt_source", "auto")),
            exclude_prefixes=getattr(args, "exclude_prefixes", ()) or (),
            include_harness=bool(getattr(args, "include_harness", False)),
            qa_scope=getattr(args, "qa_scope", None),
            qa_owasp=getattr(args, "qa_owasp", None),
            qa_cases=getattr(args, "qa_cases", None),
            qa_no_reanalyze=bool(ctx.flags.qa_no_reanalyze),
            gt_policy=gt_policy,
            artifacts=artifacts,
            exit_code=int(overall),
            checklist_pass=bool(ctx.qa_checklist_pass),
        )

        out_manifest = write_qa_calibration_manifest(suite_dir=suite_dir, manifest=manifest)
        print(f"\n🧾 Wrote QA manifest: {out_manifest}")

        # Backward-compatible alias (best-effort)
        legacy_path = (suite_dir / "analysis" / "qa_calibration_manifest.json").resolve()
        if legacy_path.exists() and str(legacy_path) != str(out_manifest):
            print(f"   (legacy alias) {legacy_path}")

    except Exception as e:
        print(f"\n❌ Failed to write QA manifest: {e}")
        overall = max(int(overall), 2)

    return int(overall)


def _qa_stage_write_suite_report(*, qa_ctx: QARunbookContext) -> Dict[str, Any]:
    """Write suite report artifacts (best-effort)."""

    rep_paths: Dict[str, Any] = {}
    try:
        from pipeline.analysis.suite.suite_report import write_suite_report

        rep_paths = write_suite_report(suite_dir=qa_ctx.suite_dir, suite_id=str(qa_ctx.suite_id))
        print("\n📄 Suite report")
        print(f"  Markdown: {rep_paths.get('out_md')}")
        print(f"  JSON    : {rep_paths.get('out_json')}")
    except Exception as e:
        print(f"\n⚠️  Failed to build suite_report: {e}")
        rep_paths = {}

    return rep_paths


def _qa_stage_append_suite_report_checks(
    checks: List[Any],
    *,
    qa_ctx: QARunbookContext,
    rep_paths: Dict[str, Any],
) -> List[Any]:
    """Surface suite_report existence as a QA warning (non-fatal)."""

    try:
        from pipeline.analysis.qa.qa_calibration_runbook import QACheck

        suite_dir = qa_ctx.suite_dir
        md_path = Path(str(rep_paths.get("out_md") or (suite_dir / "analysis" / "suite_report.md"))).resolve()
        js_path = Path(str(rep_paths.get("out_json") or (suite_dir / "analysis" / "suite_report.json"))).resolve()

        checks.append(
            QACheck(
                name="analysis/suite_report.md exists",
                ok=True,
                warn=not md_path.exists(),
                path=str(md_path),
                detail="" if md_path.exists() else "missing",
            )
        )
        checks.append(
            QACheck(
                name="analysis/suite_report.json exists",
                ok=True,
                warn=not js_path.exists(),
                path=str(js_path),
                detail="" if js_path.exists() else "missing",
            )
        )
    except Exception:
        pass

    return checks


def _qa_stage_write_checklist_artifacts(
    checks: List[Any],
    *,
    qa_ctx: QARunbookContext,
    overall: int,
) -> int:
    """Render + write checklist artifacts (JSON/MD + legacy TXT)."""

    try:
        from pipeline.analysis.qa.qa_calibration_runbook import (
            render_checklist,
            write_qa_checklist_artifacts,
        )

        report = render_checklist(list(checks), title="QA calibration checklist")
        print(report)

        out_paths = write_qa_checklist_artifacts(
            checks,
            suite_dir=qa_ctx.suite_dir,
            suite_id=str(qa_ctx.suite_id),
            title="QA calibration checklist",
        )
        print("\n📝 Wrote QA checklist artifacts")
        print(f"  JSON : {out_paths.get('out_json')}")
        print(f"  MD   : {out_paths.get('out_md')}")
        print(f"  TXT  : {out_paths.get('out_txt')}")
    except Exception as e:
        print(f"\n⚠️  Failed to write QA checklist artifacts: {e}")
        overall = max(int(overall), 2)

    return int(overall)
