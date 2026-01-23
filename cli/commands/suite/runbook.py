from __future__ import annotations

import argparse
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cli.suite_sources import _bootstrap_worktrees_from_repo_url, _parse_branches_spec
from cli.ui import _prompt_text, _prompt_yes_no
from pipeline.core import ROOT_DIR as PIPELINE_ROOT_DIR, repo_id_from_repo_url
from pipeline.orchestrator import AnalyzeRequest, RunRequest
from pipeline.pipeline import SASTBenchmarkPipeline
from pipeline.scanners import DEFAULT_SCANNERS_CSV, SUPPORTED_SCANNERS
from pipeline.suites.bundles import anchor_under_repo_root, safe_name
from pipeline.suites.layout import new_suite_id
from pipeline.suites.suite_definition import SuiteAnalysisDefaults, SuiteCase, SuiteDefinition
from pipeline.suites.suite_py_loader import load_suite_py
from pipeline.suites.suite_resolver import ResolvedSuiteRun, SuiteInputProvenance, resolve_suite_run

from .gt_tolerance_runbook import run_gt_tolerance_policy_runbook
from .materialize import (
    _build_suite_from_sources,
    _build_suite_interactively,
    _parse_scanners_str,
    _write_suite_py,
)
from .qa_calibration import (
    _default_owasp_micro_suite_cases_csv,
    _default_owasp_micro_suite_worktrees_root,
    _detect_owasp_id,
    _qa_target_owasp_ids,
)


ROOT_DIR = PIPELINE_ROOT_DIR


@dataclass(frozen=True)
class SuiteFlags:
    """Normalized mode flags derived from CLI args."""

    qa_mode: bool = False
    qa_no_reanalyze: bool = False


@dataclass
class GTToleranceSweepState:
    """Best-effort sweep/selection state for QA manifests."""

    enabled: bool = False
    candidates: List[int] = field(default_factory=list)
    report_csv: Optional[str] = None
    payload_json: Optional[str] = None
    selection_path: Optional[str] = None
    selection_warnings: List[str] = field(default_factory=list)

    payload: Optional[Dict[str, Any]] = None
    selection: Optional[Dict[str, Any]] = None

    # Policy inputs used when writing the selection file (populated at runtime).
    sweep_raw: Optional[str] = None
    auto_enabled: bool = False
    auto_min_fraction: float = 0.95


@dataclass
class SuiteRunContext:
    """Mutable context shared across suite runbook steps."""

    args: argparse.Namespace
    pipeline: SASTBenchmarkPipeline
    repo_registry: Dict[str, Dict[str, str]]
    suite_root: Path

    flags: SuiteFlags = field(default_factory=SuiteFlags)

    # Captured before any sweep/auto selection mutates args.
    gt_tolerance_initial: int = 0

    # Best-effort sweep/selection state (QA calibration).
    gt_sweep: GTToleranceSweepState = field(default_factory=GTToleranceSweepState)

    # Resolved run configuration (filled by resolve_suite_run_and_dirs).
    suite_id: str = ""
    suite_dir: Optional[Path] = None
    scanners: List[str] = field(default_factory=list)
    tolerance: int = 0
    analysis_filter: str = ""
    skip_analysis: bool = False
    provenance: Optional[SuiteInputProvenance] = None
    analysis_defaults: Optional[SuiteAnalysisDefaults] = None

    # QA checklist result (filled best-effort).
    qa_checklist_pass: Optional[bool] = None

    @classmethod
    def from_args(
        cls,
        *,
        args: argparse.Namespace,
        pipeline: SASTBenchmarkPipeline,
        repo_registry: Dict[str, Dict[str, str]],
    ) -> "SuiteRunContext":
        """Create a context with stable paths and captured mode flags.

        We anchor suite_root under the repo root unless the user passed an
        absolute path. This avoids path drift when the CLI is invoked from
        different working directories.
        """

        suite_root = anchor_under_repo_root(Path(args.suite_root).expanduser())

        flags = SuiteFlags(
            qa_mode=bool(getattr(args, "qa_calibration", False)),
            qa_no_reanalyze=bool(getattr(args, "qa_no_reanalyze", False)),
        )

        # Capture GT tolerance input *before* any sweep/auto-selection mutates args.
        gt_tolerance_initial = int(getattr(args, "gt_tolerance", 0) or 0)

        return cls(
            args=args,
            pipeline=pipeline,
            repo_registry=repo_registry,
            suite_root=suite_root,
            flags=flags,
            gt_tolerance_initial=gt_tolerance_initial,
            gt_sweep=GTToleranceSweepState(),
        )


def validate_suite_args(ctx: SuiteRunContext) -> Optional[int]:
    """Validate and normalize CLI args.

    This step handles QA calibration mode constraints and establishes stable
    defaults before any suite definition is loaded/built.

    Returns
    -------
    Optional[int]
        Exit code if the runbook should abort early, otherwise None.
    """

    args = ctx.args

    qa_mode = bool(getattr(args, "qa_calibration", False))
    qa_no_reanalyze = bool(getattr(args, "qa_no_reanalyze", False))
    ctx.flags = SuiteFlags(qa_mode=qa_mode, qa_no_reanalyze=qa_no_reanalyze)

    # Capture GT tolerance input *before* any sweep/auto-selection mutates args.
    ctx.gt_tolerance_initial = int(getattr(args, "gt_tolerance", 0) or 0)

    # Reset best-effort sweep state for this run.
    ctx.gt_sweep = GTToleranceSweepState()
    ctx.qa_checklist_pass = None

    if not qa_mode:
        return None

    # QA requires artifacts on disk.
    if args.dry_run:
        print("❌ --qa-calibration cannot be used with --dry-run (needs artifacts to validate).")
        return 2
    if args.skip_analysis:
        print("❌ --qa-calibration cannot be used with --skip-analysis (needs suite analysis + calibration).")
        return 2

    # Defensive: "latest" is reserved for selecting a previously-run suite.
    # In QA mode we always create a new suite id.
    if (args.suite_id or "").strip().lower() == "latest":
        print("⚠️  Ignoring --suite-id=latest in QA mode; generating a fresh suite id.")
        args.suite_id = None

    # Deterministic suite definition: disallow interactive prompting.
    # If no explicit suite inputs are provided, fall back to the example
    # OWASP micro-suite inputs if present.
    if not (args.suite_file or args.cases_from or args.worktrees_root or getattr(args, "repo_url", None)):
        default_wt = _default_owasp_micro_suite_worktrees_root()
        default_csv = _default_owasp_micro_suite_cases_csv()
        if default_wt is not None:
            args.worktrees_root = str(default_wt)
            print(f"🧪 QA calibration: using default worktrees-root: {default_wt}")
        elif default_csv is not None:
            args.cases_from = str(default_csv)
            print(f"🧪 QA calibration: using default cases-from CSV: {default_csv}")
        else:
            print(
                "❌ --qa-calibration requires a non-interactive suite definition source.\n"
                "Provide one of: --suite-file, --cases-from, --worktrees-root, or --repo-url (+ --branches)."
            )
            return 2

    return None


def maybe_bootstrap_worktrees(ctx: SuiteRunContext) -> None:
    """Optional bridge: build a worktrees root from a repo url + branch set."""

    args = ctx.args

    if not (getattr(args, "repo_url", None) and (not args.suite_file) and (not args.cases_from)):
        return

    branches = _parse_branches_spec(getattr(args, "branches", None))
    if ctx.flags.qa_mode and not branches:
        branches = _qa_target_owasp_ids(args)

    if not branches:
        raise SystemExit(
            "Suite worktree bootstrap requires --branches when using --repo-url "
            "(unless --qa-calibration is set, which derives branches from the QA scope)."
        )

    default_root = ROOT_DIR / "repos" / "worktrees" / repo_id_from_repo_url(str(args.repo_url))
    wt_root = Path(args.worktrees_root).expanduser() if getattr(args, "worktrees_root", None) else default_root
    wt_root = anchor_under_repo_root(wt_root)

    _bootstrap_worktrees_from_repo_url(repo_url=str(args.repo_url), branches=branches, worktrees_root=wt_root)
    args.worktrees_root = str(wt_root)

    if ctx.flags.qa_mode:
        print(f"🧪 QA calibration: bootstrapped worktrees-root: {wt_root}")
    else:
        print(f"🌿 Suite worktrees ready: {wt_root}")


def load_or_build_suite_def(ctx: SuiteRunContext) -> SuiteDefinition:
    """Load suite definition from a file, sources (CSV/worktrees), or interactively."""

    args = ctx.args

    if args.suite_file:
        p = Path(args.suite_file).expanduser().resolve()
        if p.suffix.lower() in (".yaml", ".yml"):
            raise SystemExit(
                f"YAML suite definitions are no longer allowed at runtime: {p}\n"
                "Use scripts/migrate_suite_yaml_to_py.py to convert to a .py suite file."
            )
        return load_suite_py(p)

    if args.cases_from or args.worktrees_root:
        return _build_suite_from_sources(args)

    return _build_suite_interactively(args, repo_registry=ctx.repo_registry)


def apply_qa_case_selection(ctx: SuiteRunContext, suite_def: SuiteDefinition) -> Tuple[SuiteDefinition, Optional[int]]:
    """Restrict the suite to the requested OWASP slice in QA mode."""

    if not ctx.flags.qa_mode:
        return suite_def, None

    args = ctx.args

    targets_list = _qa_target_owasp_ids(args)
    targets = set(targets_list)
    scope_label = "custom" if getattr(args, "qa_owasp", None) else (getattr(args, "qa_scope", None) or "smoke")

    selected_cases: List[SuiteCase] = []
    skipped_case_ids: List[str] = []
    for sc in suite_def.cases:
        c = sc.case
        oid = _detect_owasp_id(c.case_id, c.branch, c.label)
        if oid and oid in targets:
            selected_cases.append(sc)
        else:
            skipped_case_ids.append(c.case_id)

    if not selected_cases:
        found_ids = sorted(
            {
                _detect_owasp_id(sc.case.case_id, sc.case.branch, sc.case.label)
                for sc in suite_def.cases
                if _detect_owasp_id(sc.case.case_id, sc.case.branch, sc.case.label)
            }
        )
        print(
            "❌ QA calibration selection produced 0 cases.\n"
            f"Requested scope: {scope_label} (targets={sorted(targets)})\n"
            f"Found OWASP ids in suite: {found_ids}\n"
            "Tip: use --qa-owasp to override or point --cases-from/--worktrees-root at a suite with OWASP-labelled cases."
        )
        return suite_def, 2

    selected_cases = sorted(selected_cases, key=lambda sc: sc.case.case_id)
    suite_def = SuiteDefinition(
        suite_id=suite_def.suite_id,
        scanners=suite_def.scanners,
        cases=selected_cases,
        analysis=suite_def.analysis,
    )

    print("\n🧪 QA calibration runbook")
    print(f"- scope: {scope_label}")
    print(f"- owasp targets: {targets_list}")
    print(f"- selected cases: {len(selected_cases)}")
    if skipped_case_ids:
        print(f"- skipped cases: {len(skipped_case_ids)}")

    return suite_def, None


def resolve_suite_run_and_dirs(ctx: SuiteRunContext, suite_def: SuiteDefinition) -> Tuple[Optional[ResolvedSuiteRun], Optional[int]]:
    """Apply CLI overrides + resolve the suite run manifest on disk."""

    args = ctx.args

    suite_id = str(args.suite_id) if args.suite_id else (suite_def.suite_id or new_suite_id())

    scanners: List[str]
    if args.scanners:
        scanners = _parse_scanners_str(args.scanners)
    elif suite_def.scanners:
        scanners = [t for t in suite_def.scanners if t in SUPPORTED_SCANNERS]
    else:
        scanners = _parse_scanners_str(DEFAULT_SCANNERS_CSV)

    if not scanners:
        raise SystemExit("No valid scanners specified for suite mode.")

    # If suite file is present, let it drive analysis defaults; otherwise use CLI.
    if args.suite_file:
        tolerance = int(suite_def.analysis.tolerance)
        analysis_filter = str(suite_def.analysis.filter)
        skip_analysis = bool(args.skip_analysis) or bool(suite_def.analysis.skip)
    else:
        tolerance = int(args.tolerance)
        analysis_filter = str(args.analysis_filter)
        skip_analysis = bool(args.skip_analysis)

    if ctx.flags.qa_mode and skip_analysis:
        print("❌ --qa-calibration cannot run with analysis skipped (suite_def.analysis.skip / --skip-analysis).")
        return None, 2

    suite_dir = (ctx.suite_root / safe_name(suite_id)).resolve()
    suite_dir.mkdir(parents=True, exist_ok=True)

    # If user provided a suite file, copy it into the suite folder for provenance
    # *before* writing suite.json so the run folder is self-contained.
    suite_input_copy: Optional[str] = None
    if args.suite_file:
        try:
            src = Path(args.suite_file).expanduser().resolve()
            dst = suite_dir / "suite_input.py"
            if src != dst:
                shutil.copyfile(src, dst)
            suite_input_copy = dst.name
        except Exception:
            # best-effort only
            suite_input_copy = None

    prov = SuiteInputProvenance(
        suite_file=suite_input_copy,
        cases_from_csv=(Path(args.cases_from).name if args.cases_from else None),
        worktrees_root=(Path(args.worktrees_root).name if args.worktrees_root else None),
        built_interactively=bool((not args.suite_file) and (not args.cases_from) and (not args.worktrees_root)),
    )

    analysis_defaults = SuiteAnalysisDefaults(
        skip=bool(skip_analysis),
        tolerance=int(tolerance),
        filter=str(analysis_filter),
    )

    resolved_run = resolve_suite_run(
        suite_def=suite_def,
        suite_id=suite_id,
        suite_root=ctx.suite_root,
        scanners=scanners,
        analysis=analysis_defaults,
        suite_kind="qa_calibration" if ctx.flags.qa_mode else "benchmark",
        provenance=prov,
        repo_registry=ctx.repo_registry,
        ensure_dirs=True,
    )

    # Use the canonical, sanitized identifiers from the resolver.
    ctx.suite_id = resolved_run.suite_id
    ctx.suite_dir = resolved_run.suite_dir
    ctx.scanners = list(scanners)
    ctx.tolerance = int(tolerance)
    ctx.analysis_filter = str(analysis_filter)
    ctx.skip_analysis = bool(skip_analysis)
    ctx.provenance = prov
    ctx.analysis_defaults = analysis_defaults

    return resolved_run, None


def maybe_write_replay_file(ctx: SuiteRunContext, resolved_run: ResolvedSuiteRun) -> None:
    """Optionally write a Python replay file for interactively built suites."""

    prov = ctx.provenance
    if not (prov and prov.built_interactively):
        return

    if not _prompt_yes_no(
        "Save a replay file for this interactive suite? (rerun later without prompts)",
        default=False,
    ):
        return

    suite_dir = resolved_run.suite_dir
    suite_id = resolved_run.suite_id
    scanners = list(ctx.scanners)
    analysis_defaults = ctx.analysis_defaults or SuiteAnalysisDefaults(skip=False, tolerance=0, filter="")

    replay_dir = suite_dir / "replay"
    default_out = replay_dir / "replay_suite.py"
    raw_out = _prompt_text("Replay file path (name or path)", default=str(default_out)).strip()

    # If the user types a bare name like "Test1" (no slashes), treat it as a filename
    # under suite_dir/replay/. This prevents accidental files being created in the repo root
    # and keeps replay artifacts co-located with the suite run.
    if not raw_out:
        out_path = default_out
    else:
        s = raw_out.strip().strip('"').strip("'")
        if ("/" not in s) and ("\\" not in s):
            name = safe_name(Path(s).stem) or "suite_definition"
            out_path = replay_dir / f"{name}.py"
        else:
            p = Path(s).expanduser()
            if not p.is_absolute():
                p = suite_dir / p
            if p.suffix.lower() != ".py":
                p = p.with_suffix(".py")
            out_path = p

    to_write = SuiteDefinition(
        suite_id=suite_id,
        scanners=scanners,
        cases=[rc.suite_case for rc in resolved_run.cases],
        analysis=analysis_defaults,
    )
    try:
        written = _write_suite_py(out_path, to_write)
        print(f"  ✅ Wrote suite replay file: {written}")

        # Write a small copy/paste command next to the replay file.
        # Best-effort only; failure should not affect the suite run.
        try:
            try:
                rel = written.relative_to(ROOT_DIR).as_posix()
            except Exception:
                rel = str(written)

            suite_file_arg = f'"{rel}"'
            cmd_text = "\n".join(
                [
                    "# Generated replay command for this interactive suite snapshot.",
                    "# Tip: choose a NEW suite id to avoid mixing outputs with the original run.",
                    f"python sast_cli.py --mode suite --suite-file {suite_file_arg} --suite-id <new_suite_id>",
                    "",
                    "# (Advanced) Replay into the same suite id (may overwrite summary/manifests):",
                    f"python sast_cli.py --mode suite --suite-file {suite_file_arg}",
                    "",
                ]
            )
            cmd_path = written.parent / "replay_command.txt"
            cmd_path.write_text(cmd_text, encoding="utf-8")
            print(f"  ✅ Wrote replay command: {cmd_path}")
        except Exception as e:
            print(f"  ⚠️  Failed to write replay command file: {e}")
    except Exception as e:
        print(f"  ⚠️  Failed to write suite replay .py: {e}")


def run_suite_cases(ctx: SuiteRunContext, resolved_run: ResolvedSuiteRun) -> int:
    """Execute all resolved suite cases through the pipeline."""

    args = ctx.args
    suite_id = resolved_run.suite_id
    suite_root = resolved_run.suite_root

    scanners = list(ctx.scanners)
    tolerance = int(ctx.tolerance or 0)
    analysis_filter = str(ctx.analysis_filter or "")
    skip_analysis = bool(ctx.skip_analysis)

    print("\n🚀 Running suite")
    print(f"  Suite id : {suite_id}")
    print(f"  Suite dir: {resolved_run.suite_dir}")
    print(f"  Cases    : {len(resolved_run.cases)}")
    print(f"  Scanners : {', '.join(scanners)}")

    overall = 0
    for idx, rc in enumerate(resolved_run.cases, start=1):
        sc = rc.suite_case
        repo_id = rc.repo_id
        case = sc.case
        print("\n" + "=" * 72)
        print(f"🧪 Case {idx}/{len(resolved_run.cases)}: {case.case_id} ({case.label})")
        if case.repo.repo_url:
            print(f"  Repo URL : {case.repo.repo_url}")
        if case.repo.repo_path:
            print(f"  Repo path: {case.repo.repo_path}")

        req = RunRequest(
            invocation_mode="benchmark",
            case=case,
            repo_id=repo_id,
            scanners=scanners,
            suite_root=suite_root,
            suite_id=suite_id,
            use_suite=True,
            dry_run=bool(args.dry_run),
            quiet=bool(args.quiet),
            skip_analysis=bool(skip_analysis),
            tolerance=int(tolerance),
            gt_tolerance=int(getattr(args, "gt_tolerance", 0)),
            gt_source=str(getattr(args, "gt_source", "auto")),
            analysis_filter=str(analysis_filter),
            exclude_prefixes=getattr(args, "exclude_prefixes", ()) or (),
            include_harness=bool(getattr(args, "include_harness", False)),
            sonar_project_key=sc.overrides.sonar_project_key or args.sonar_project_key,
            aikido_git_ref=sc.overrides.aikido_git_ref or args.aikido_git_ref,
            argv=list(sys.argv),
            python_executable=sys.executable,
        )

        rc_code = int(ctx.pipeline.run(req))
        overall = max(overall, rc_code)

    return overall


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
    qa_no_reanalyze = ctx.flags.qa_no_reanalyze

    suite_id = resolved_run.suite_id
    suite_root = resolved_run.suite_root
    suite_dir = resolved_run.suite_dir

    scanners = list(ctx.scanners)
    tolerance = int(ctx.tolerance or 0)
    analysis_filter = str(ctx.analysis_filter or "")
    skip_analysis = bool(ctx.skip_analysis)

    overall = max(overall, build_suite_artifacts(ctx, resolved_run))

    # ------------------------------------------------------------------
    # QA calibration runbook: second pass analyze + deterministic checklist
    # ------------------------------------------------------------------
    if qa_mode and (not bool(args.dry_run)) and (not bool(skip_analysis)):
        if qa_no_reanalyze:
            print("\n🧪 QA calibration: skipping re-analyze pass (--qa-no-reanalyze).")
        else:
            print("\n🔁 QA calibration: re-analyzing cases to apply triage calibration")
            for j, rc2 in enumerate(resolved_run.cases, start=1):
                c2 = rc2.suite_case.case
                print("\n" + "-" * 72)
                print(f"🔁 Analyze {j}/{len(resolved_run.cases)}: {c2.case_id}")

                # Explicit case_path prevents case-id normalization surprises.
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
                        gt_tolerance=int(getattr(args, "gt_tolerance", 0)),
                        gt_source=str(getattr(args, "gt_source", "auto")),
                        analysis_filter=str(analysis_filter),
                        exclude_prefixes=getattr(args, "exclude_prefixes", ()) or (),
                        include_harness=bool(getattr(args, "include_harness", False)),
                        skip_suite_aggregate=True,
                    )
                    rc_code2 = int(ctx.pipeline.analyze(areq))
                except Exception as e:
                    print(f"  ❌ re-analyze failed for {c2.case_id}: {e}")
                    rc_code2 = 2

                overall = max(overall, rc_code2)

        # Suite-level evaluation (triage ranking quality + tool utility)
        try:
            from pipeline.analysis.suite.suite_triage_eval import build_triage_eval

            ev = build_triage_eval(suite_dir=suite_dir, suite_id=suite_id)

            print("\n📈 Suite triage_eval (QA)")
            print(f"  Summary : {ev.get('out_summary_json')}")
            print(f"  By-case : {ev.get('out_by_case_csv')}")
            print(f"  Tools   : {ev.get('out_tool_utility_csv')}")

            if ev.get("out_tool_marginal_csv"):
                print(f"  Marginal: {ev.get('out_tool_marginal_csv')}")
        except Exception as e:
            print(f"\n⚠️  Failed to build suite triage_eval (QA): {e}")

        # Validate suite artifacts (filesystem-first).
        checks: List[object] = []
        try:
            from pipeline.analysis.qa.qa_calibration_runbook import (
                all_ok,
                validate_calibration_suite_artifacts,
            )

            checks = validate_calibration_suite_artifacts(
                suite_dir=suite_dir,
                require_scored_queue=(not qa_no_reanalyze),
                expect_calibration=True,
                expect_gt_tolerance_sweep=bool(ctx.gt_sweep.sweep_raw or ctx.gt_sweep.auto_enabled),
                expect_gt_tolerance_selection=True,
            )

            ctx.qa_checklist_pass = bool(all_ok(checks))
        except Exception as e:
            print(f"\n❌ QA calibration validation failed: {e}")
            overall = max(overall, 2)
            ctx.qa_checklist_pass = False
            checks = []

        if not bool(ctx.qa_checklist_pass):
            overall = max(overall, 2)

        # QA manifest (best-effort). Write even on FAIL for CI scraping.
        try:
            from pipeline.analysis.qa.qa_calibration_manifest import (
                GTTolerancePolicyRecord,
                build_qa_calibration_manifest,
                write_qa_calibration_manifest,
            )

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
                suite_id=str(suite_id),
                suite_dir=suite_dir,
                argv=list(sys.argv),
                scanners=list(scanners),
                tolerance=int(tolerance),
                analysis_filter=str(analysis_filter),
                gt_source=str(getattr(args, "gt_source", "auto")),
                exclude_prefixes=getattr(args, "exclude_prefixes", ()) or (),
                include_harness=bool(getattr(args, "include_harness", False)),
                qa_scope=getattr(args, "qa_scope", None),
                qa_owasp=getattr(args, "qa_owasp", None),
                qa_cases=getattr(args, "qa_cases", None),
                qa_no_reanalyze=bool(qa_no_reanalyze),
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
            overall = max(overall, 2)

        # Suite report (human-friendly).
        rep_paths: Dict[str, Any] = {}
        try:
            from pipeline.analysis.suite.suite_report import write_suite_report

            rep_paths = write_suite_report(suite_dir=suite_dir, suite_id=str(suite_id))
            print("\n📄 Suite report")
            print(f"  Markdown: {rep_paths.get('out_md')}")
            print(f"  JSON    : {rep_paths.get('out_json')}")
        except Exception as e:
            print(f"\n⚠️  Failed to build suite_report: {e}")
            rep_paths = {}

        # Surface suite_report as a QA warning if missing (non-fatal).
        try:
            from pipeline.analysis.qa.qa_calibration_runbook import QACheck

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

        # Final step: render + write checklist artifacts (JSON/MD + legacy TXT).
        try:
            from pipeline.analysis.qa.qa_calibration_runbook import (
                render_checklist,
                write_qa_checklist_artifacts,
            )

            report = render_checklist(list(checks), title="QA calibration checklist")
            print(report)

            out_paths = write_qa_checklist_artifacts(
                checks,
                suite_dir=suite_dir,
                suite_id=str(suite_id),
                title="QA calibration checklist",
            )
            print("\n📝 Wrote QA checklist artifacts")
            print(f"  JSON : {out_paths.get('out_json')}")
            print(f"  MD   : {out_paths.get('out_md')}")
            print(f"  TXT  : {out_paths.get('out_txt')}")
        except Exception as e:
            print(f"\n⚠️  Failed to write QA checklist artifacts: {e}")
            overall = max(overall, 2)

    return int(overall)
