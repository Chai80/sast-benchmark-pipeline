"""cli.commands.suite.runbook_steps.resolve

Suite runbook resolution steps:

* validate CLI args (QA calibration constraints)
* optionally bootstrap worktrees
* load/build a suite definition
* resolve suite run layout (dirs + suite.json)
* optionally write an interactive replay file
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import List, Optional, Tuple

from cli.suite_sources import _bootstrap_worktrees_from_repo_url, _parse_branches_spec
from cli.ui import _prompt_text, _prompt_yes_no
from pipeline.core import repo_id_from_repo_url
from pipeline.scanners import DEFAULT_SCANNERS_CSV, SUPPORTED_SCANNERS
from pipeline.suites.bundles import anchor_under_repo_root, safe_name
from pipeline.suites.layout import new_suite_id
from pipeline.suites.suite_definition import (
    SuiteAnalysisDefaults,
    SuiteCase,
    SuiteDefinition,
)
from pipeline.suites.suite_py_loader import load_suite_py
from pipeline.suites.suite_resolver import (
    ResolvedSuiteRun,
    SuiteInputProvenance,
    resolve_suite_run,
)

from ..materialize import (
    _build_suite_from_sources,
    _build_suite_interactively,
    _parse_scanners_str,
    _write_suite_py,
)
from ..qa_calibration import (
    _default_owasp_micro_suite_cases_csv,
    _default_owasp_micro_suite_worktrees_root,
    _detect_owasp_id,
    _qa_target_owasp_ids,
)
from .model import GTToleranceSweepState, ROOT_DIR, SuiteFlags, SuiteRunContext


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
        print(
            "❌ --qa-calibration cannot be used with --skip-analysis (needs suite analysis + calibration)."
        )
        return 2

    # Defensive: "latest" is reserved for selecting a previously-run suite.
    # In QA mode we always create a new suite id.
    if (args.suite_id or "").strip().lower() == "latest":
        print("⚠️  Ignoring --suite-id=latest in QA mode; generating a fresh suite id.")
        args.suite_id = None

    # Deterministic suite definition: disallow interactive prompting.
    # If no explicit suite inputs are provided, fall back to the example
    # OWASP micro-suite inputs if present.
    if not (
        args.suite_file or args.cases_from or args.worktrees_root or getattr(args, "repo_url", None)
    ):
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
    wt_root = (
        Path(args.worktrees_root).expanduser()
        if getattr(args, "worktrees_root", None)
        else default_root
    )
    wt_root = anchor_under_repo_root(wt_root)

    _bootstrap_worktrees_from_repo_url(
        repo_url=str(args.repo_url), branches=branches, worktrees_root=wt_root
    )
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


def apply_qa_case_selection(
    ctx: SuiteRunContext, suite_def: SuiteDefinition
) -> Tuple[SuiteDefinition, Optional[int]]:
    """Restrict the suite to the requested OWASP slice in QA mode."""

    if not ctx.flags.qa_mode:
        return suite_def, None

    args = ctx.args

    targets_list = _qa_target_owasp_ids(args)
    targets = set(targets_list)
    scope_label = (
        "custom"
        if getattr(args, "qa_owasp", None)
        else (getattr(args, "qa_scope", None) or "smoke")
    )

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


def resolve_suite_run_and_dirs(
    ctx: SuiteRunContext, suite_def: SuiteDefinition
) -> Tuple[Optional[ResolvedSuiteRun], Optional[int]]:
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
        print(
            "❌ --qa-calibration cannot run with analysis skipped (suite_def.analysis.skip / --skip-analysis)."
        )
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
        built_interactively=bool(
            (not args.suite_file) and (not args.cases_from) and (not args.worktrees_root)
        ),
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
    analysis_defaults = ctx.analysis_defaults or SuiteAnalysisDefaults(
        skip=False, tolerance=0, filter=""
    )

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
