"""cli.commands.suite.gt_tolerance_runbook

Small, explicit runbook for GT tolerance policy in QA calibration runs.

Why this exists
---------------
The suite runbook needs to support an optional GT tolerance sweep and an
optional auto-selection strategy. The original inline implementation made the
core suite flow hard to read.

This module keeps the policy logic in one place:

* detect whether a sweep is requested
* run the sweep and (optionally) auto-select a tolerance
* finalize per-case analysis once for the effective tolerance
* write a small selection artifact for CI reproducibility

Design goals
------------
* filesystem-first and best-effort (keep producing artifacts even on partial failures)
* minimal branching at the call site (the main suite runbook stays readable)
* no new frameworks or heavy abstractions
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Mapping

from pipeline.orchestrator import AnalyzeRequest
from pipeline.suites.bundles import safe_name


if TYPE_CHECKING:
    # Avoid runtime import cycles (runbook.py imports this module).
    from .runbook import SuiteRunContext
    from pipeline.suites.suite_resolver import ResolvedSuiteRun
def _build_selection_payload(ctx: "SuiteRunContext", *, eff_tol: int) -> Dict[str, Any]:
    """Build the selection mapping written to analysis/gt_tolerance_selection.json.

    This intentionally mirrors the previous inline behavior.
    """

    selection: Dict[str, Any] = {}
    if isinstance(ctx.gt_sweep.selection, Mapping):
        selection = dict(ctx.gt_sweep.selection)

    if not selection:
        selection = {
            "schema_version": "gt_tolerance_selection_v1",
            "selected_gt_tolerance": int(eff_tol),
            "mode": "explicit",
            "warnings": [],
        }

    # Always reflect the effective tolerance at write-time.
    selection["selected_gt_tolerance"] = int(eff_tol)

    selection.setdefault("policy", {})
    if isinstance(selection["policy"], dict):
        selection["policy"].update(
            {
                "initial_gt_tolerance": int(ctx.gt_tolerance_initial),
                "effective_gt_tolerance": int(eff_tol),
                "sweep_raw": str(ctx.gt_sweep.sweep_raw) if ctx.gt_sweep.sweep_raw is not None else None,
                "sweep_candidates": [int(x) for x in (ctx.gt_sweep.candidates or [])]
                if bool(ctx.gt_sweep.enabled)
                else [],
                "auto_enabled": bool(ctx.gt_sweep.auto_enabled),
                "auto_min_fraction": float(ctx.gt_sweep.auto_min_fraction)
                if bool(ctx.gt_sweep.auto_enabled)
                else None,
                "gt_source": str(getattr(ctx.args, "gt_source", "auto")),
            }
        )

    return selection


def run_gt_tolerance_policy_runbook(ctx: "SuiteRunContext", resolved_run: "ResolvedSuiteRun", *, overall: int) -> int:
    """Apply GT tolerance policy for QA calibration.

    This function is safe to call from the main suite runbook.
    It is a no-op outside QA calibration mode.

    Parameters
    ----------
    ctx:
        Shared suite run context.
    resolved_run:
        The resolved suite run (cases + paths).
    overall:
        Current exit code contribution to update.

    Returns
    -------
    int
        Updated exit code contribution.
    """

    # Non-QA runs do not use the sweep/selection artifacts.
    if not bool(getattr(ctx.flags, "qa_mode", False)):
        return int(overall)

    args = ctx.args

    if bool(getattr(args, "dry_run", False)) or bool(getattr(args, "skip_analysis", False)):
        return int(overall)

    suite_id = resolved_run.suite_id
    suite_root = resolved_run.suite_root
    suite_dir = Path(resolved_run.suite_dir).resolve()

    scanners = list(ctx.scanners)
    tolerance = int(ctx.tolerance or 0)
    analysis_filter = str(ctx.analysis_filter or "")

    # ------------------------------------------------------------------
    # 1) Detect sweep policy.
    # ------------------------------------------------------------------
    sweep_raw = getattr(args, "gt_tolerance_sweep", None)
    sweep_auto = bool(getattr(args, "gt_tolerance_auto", False))
    sweep_min_frac = float(getattr(args, "gt_tolerance_auto_min_fraction", 0.95) or 0.95)

    ctx.gt_sweep.sweep_raw = str(sweep_raw) if sweep_raw is not None else None
    ctx.gt_sweep.auto_enabled = bool(sweep_auto)
    ctx.gt_sweep.auto_min_fraction = float(sweep_min_frac)

    sweep_requested = bool(sweep_raw or sweep_auto)

    # ------------------------------------------------------------------
    # 2) Run sweep (optional) and auto-select (optional).
    # ------------------------------------------------------------------
    if sweep_requested:
        ctx.gt_sweep.enabled = True
        ctx.gt_sweep.report_csv = str((suite_dir / "analysis" / "_tables" / "gt_tolerance_sweep_report.csv").resolve())
        ctx.gt_sweep.payload_json = str((suite_dir / "analysis" / "gt_tolerance_sweep.json").resolve())

        try:
            from pipeline.analysis.suite.gt_tolerance_sweep import (
                disable_suite_calibration,
                parse_gt_tolerance_candidates,
                run_gt_tolerance_sweep,
                select_gt_tolerance_auto,
            )

            candidates = parse_gt_tolerance_candidates(sweep_raw)
            ctx.gt_sweep.candidates = list(candidates)

            sweep_payload = run_gt_tolerance_sweep(
                pipeline=ctx.pipeline,
                suite_root=suite_root,
                suite_id=suite_id,
                suite_dir=suite_dir,
                cases=[rc.suite_case.case for rc in resolved_run.cases],
                tools=scanners,
                tolerance=int(tolerance),
                gt_source=str(getattr(args, "gt_source", "auto")),
                analysis_filter=str(analysis_filter),
                exclude_prefixes=tuple(getattr(args, "exclude_prefixes", ()) or ()),
                include_harness=bool(getattr(args, "include_harness", False)),
                candidates=candidates,
            )

            # Keep canonical report path for downstream manifests.
            ctx.gt_sweep.report_csv = str(sweep_payload.get("out_report_csv") or ctx.gt_sweep.report_csv)
            ctx.gt_sweep.payload = dict(sweep_payload) if isinstance(sweep_payload, Mapping) else None

            if sweep_auto:
                sel = select_gt_tolerance_auto(
                    sweep_payload.get("rows") or [],
                    min_fraction=sweep_min_frac,
                )
                chosen = int(sel.get("selected_gt_tolerance", int(getattr(args, "gt_tolerance", 0))))

                ctx.gt_sweep.selection = dict(sel)
                ctx.gt_sweep.selection_warnings = [str(w) for w in (sel.get("warnings") or []) if str(w).strip()]

                print(f"\n✅ GT tolerance auto-selected: {chosen}")
                if ctx.gt_sweep.selection_warnings:
                    for w in ctx.gt_sweep.selection_warnings:
                        print(f"  ⚠️  {w}")

                try:
                    setattr(args, "gt_tolerance", chosen)
                except Exception:
                    # Best-effort; downstream reads args.gt_tolerance.
                    pass
            else:
                # Explicit tolerance path: still record for CI reproducibility.
                ctx.gt_sweep.selection = {
                    "schema_version": "gt_tolerance_selection_v1",
                    "selected_gt_tolerance": int(getattr(args, "gt_tolerance", 0) or 0),
                    "mode": "explicit",
                    "warnings": [],
                }
                print("\nℹ️  GT tolerance sweep complete (no auto selection; continuing with --gt-tolerance)")

            # ------------------------------------------------------------------
            # 3) Finalize per-case analysis once for the effective tolerance.
            # ------------------------------------------------------------------
            eff_tol = int(getattr(args, "gt_tolerance", 0))
            print(f"\n🔁 Finalizing suite calibration build for gt_tolerance={eff_tol}")

            # Ensure per-case analysis uses baseline ordering for triage_rank.
            disable_suite_calibration(suite_dir)

            for j, rc2 in enumerate(resolved_run.cases, start=1):
                c2 = rc2.suite_case.case
                print("\n" + "-" * 72)
                print(f"🔁 Analyze (finalize) {j}/{len(resolved_run.cases)}: {c2.case_id}")

                case_dir = (suite_dir / "cases" / safe_name(c2.case_id)).resolve()
                try:
                    areq = AnalyzeRequest(
                        metric="suite",
                        case=c2,
                        suite_root=suite_root,
                        suite_id=suite_id,
                        case_path=str(case_dir),
                        tools=tuple(scanners),
                        tolerance=int(tolerance),
                        gt_tolerance=int(eff_tol),
                        gt_source=str(getattr(args, "gt_source", "auto")),
                        analysis_filter=str(analysis_filter),
                        exclude_prefixes=tuple(getattr(args, "exclude_prefixes", ()) or ()),
                        include_harness=bool(getattr(args, "include_harness", False)),
                        skip_suite_aggregate=True,
                    )
                    rc_code2 = int(ctx.pipeline.analyze(areq))
                except Exception as e:
                    print(f"  ❌ analyze finalize failed for {c2.case_id}: {e}")
                    rc_code2 = 2

                overall = max(int(overall), int(rc_code2))

        except Exception as e:
            print(f"\n❌ GT tolerance sweep failed: {e}")
            # In QA mode, requested sweeps are first-class; fail the run (but keep going).
            overall = max(int(overall), 2)
            ctx.gt_sweep.selection_warnings = list(ctx.gt_sweep.selection_warnings or []) + [f"sweep_failed: {e}"]

    # ------------------------------------------------------------------
    # 4) Always write the selection artifact in QA mode.
    # ------------------------------------------------------------------
    try:
        from pipeline.analysis.suite.gt_tolerance_sweep import write_gt_tolerance_selection

        eff_tol = int(getattr(args, "gt_tolerance", 0) or 0)
        selection = _build_selection_payload(ctx, eff_tol=eff_tol)

        out_sel = write_gt_tolerance_selection(
            suite_dir=suite_dir,
            selection=selection,
            sweep_payload=ctx.gt_sweep.payload,
        )
        ctx.gt_sweep.selection_path = str(out_sel)
        print(f"\n🧾 Wrote GT tolerance selection: {out_sel}")
    except Exception as e:
        print(f"\n❌ Failed to write GT tolerance selection file: {e}")
        overall = max(int(overall), 2)

    return int(overall)
