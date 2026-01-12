from __future__ import annotations

import argparse
import pprint
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cli.common import derive_runs_repo_name, parse_csv
from cli.ui import choose_from_menu, _parse_index_selection, _prompt_text, _prompt_yes_no
from cli.suite_sources import (
    _case_id_from_pathlike,
    _discover_git_checkouts_under,
    _load_suite_cases_from_csv,
    _load_suite_cases_from_worktrees_root,
    _resolve_repo_for_suite_case_interactive,
    _suite_case_from_repo_path,
)
from pipeline.suites.bundles import anchor_under_repo_root, safe_name
from pipeline.core import ROOT_DIR as PIPELINE_ROOT_DIR
from pipeline.suites.layout import new_suite_id
from pipeline.models import CaseSpec
from pipeline.orchestrator import RunRequest
from pipeline.pipeline import SASTBenchmarkPipeline
from pipeline.scanners import DEFAULT_SCANNERS_CSV, SUPPORTED_SCANNERS
from pipeline.suites.suite_definition import (
    SuiteAnalysisDefaults,
    SuiteCase,
    SuiteCaseOverrides,
    SuiteDefinition,
)
from pipeline.suites.suite_py_loader import load_suite_py
from pipeline.suites.suite_resolver import SuiteInputProvenance, resolve_suite_run

ROOT_DIR = PIPELINE_ROOT_DIR


def _parse_scanners_str(value: str) -> List[str]:
    raw = parse_csv(value)
    scanners = [t for t in raw if t in SUPPORTED_SCANNERS]
    unknown = [t for t in raw if t not in SUPPORTED_SCANNERS]
    if unknown:
        print(f"  ⚠️  ignoring unknown scanners: {', '.join(unknown)}")
    return scanners


def _build_suite_interactively(args: argparse.Namespace, *, repo_registry: Dict[str, Dict[str, str]]) -> SuiteDefinition:
    print("\n🧩 Suite mode: run multiple cases under one suite id.")
    print("   - Use this for scanning many repos or many branches/worktrees.")
    print("   - Replay files are optional; suite.json/case.json/run.json are always written.\n")

    suite_id_in = _prompt_text("Suite id (press Enter to auto-generate)", default="").strip()
    suite_id = suite_id_in or new_suite_id()

    default_scanners_csv = args.scanners or DEFAULT_SCANNERS_CSV
    scanners_csv = _prompt_text("Scanners to run (comma-separated)", default=default_scanners_csv)
    scanners = _parse_scanners_str(scanners_csv)
    if not scanners:
        raise SystemExit("No valid scanners selected.")

    analysis = SuiteAnalysisDefaults(
        skip=bool(args.skip_analysis),
        tolerance=int(args.tolerance),
        filter=str(args.analysis_filter),
    )

    cases: List[SuiteCase] = []
    seen_case_ids: set[str] = set()

    print("\nAdd cases to the suite (each case is one repo/checkout).")
    print("When you're done, choose 'Finish suite definition'.\n")

    while True:
        action = choose_from_menu(
            "Add a case:",
            {
                "add": "Add a new case",
                "add_worktrees": "Add cases from local worktrees",
                "add_csv": "Add cases from CSV file (legacy / CI)",
                "done": "Finish suite definition",
            },
        )
        if action == "done":
            break

        if action == "add_worktrees":
            # Discover git checkouts under repos/worktrees/<something> and add many cases at once.
            base = (ROOT_DIR / "repos" / "worktrees").resolve()
            root: Path
            if base.exists():
                candidates = [p for p in base.iterdir() if p.is_dir()]
            else:
                candidates = []

            if candidates:
                opts: Dict[str, object] = {p.name: str(p) for p in sorted(candidates, key=lambda p: p.name)}
                opts["custom"] = "Enter a custom worktrees folder path"
                choice = choose_from_menu("Choose a worktrees folder:", opts)
                if choice == "custom":
                    entered = _prompt_text("Worktrees folder path", default=str(base)).strip()
                    root = Path(entered).expanduser().resolve()
                else:
                    root = (base / choice).resolve()
            else:
                entered = _prompt_text("Worktrees folder path", default=str(base)).strip()
                root = Path(entered).expanduser().resolve()

            discovered = _discover_git_checkouts_under(root)
            if not discovered:
                print(f"  ❌ No git checkouts found under: {root}")
                continue

            rels = []
            for d in discovered:
                try:
                    rels.append(d.relative_to(root).as_posix())
                except Exception:
                    rels.append(d.name)

            print("\nDiscovered worktrees:")
            for i, rel in enumerate(rels, start=1):
                print(f"[{i}] {rel}")

            raw_sel = _prompt_text("Select worktrees by number (e.g., 1,3-5) or 'all'", default="all")
            sel = _parse_index_selection(raw_sel, n=len(rels))
            if not sel:
                print("  ⚠️  No worktrees selected.")
                continue

            added = 0
            for i in sel:
                rel = rels[i]
                repo_dir = discovered[i]

                proposed_id = _case_id_from_pathlike(rel)
                case_id = proposed_id
                k = 2
                while case_id in seen_case_ids:
                    case_id = f"{proposed_id}_{k}"
                    k += 1

                sc = _suite_case_from_repo_path(
                    case_id=case_id,
                    repo_path=repo_dir,
                    label=rel,
                    branch=rel,
                )

                cases.append(sc)
                seen_case_ids.add(case_id)
                added += 1

            print(f"  ✅ Added {added} case(s) from worktrees.")
            continue

        if action == "add_csv":
            csv_in = _prompt_text("Cases CSV path", default="inputs/suite_inputs/cases.csv").strip()
            csv_path = Path(csv_in).expanduser().resolve()
            loaded = _load_suite_cases_from_csv(csv_path)
            if not loaded:
                print(f"  ⚠️  No cases loaded from: {csv_path}")
                continue

            added = 0
            for sc in loaded:
                cid = safe_name(sc.case.case_id)
                if cid in seen_case_ids:
                    print(f"  ⚠️  Skipping duplicate case_id from CSV: {cid}")
                    continue
                # Ensure the case_id is safe
                c = sc.case
                if cid != c.case_id:
                    sc = SuiteCase(case=CaseSpec(**{**c.__dict__, 'case_id': cid}), overrides=sc.overrides)
                cases.append(sc)
                seen_case_ids.add(cid)
                added += 1

            print(f"  ✅ Added {added} case(s) from CSV.")
            continue

        # Default: add a single case via preset/custom/local
        repo_spec, label, _repo_id = _resolve_repo_for_suite_case_interactive(repo_registry=repo_registry)

        runs_repo_name = derive_runs_repo_name(
            repo_url=repo_spec.repo_url,
            repo_path=repo_spec.repo_path,
            fallback=label,
        )

        proposed = runs_repo_name
        raw_case_id = _prompt_text("Case id (folder + DB key)", default=proposed).strip() or proposed
        case_id = safe_name(raw_case_id)
        if case_id != raw_case_id:
            print(f"  ⚠️  case_id sanitized to: {case_id}")

        if case_id in seen_case_ids:
            print(f"  ❌ case_id '{case_id}' already exists in this suite. Pick a different one.")
            continue

        seen_case_ids.add(case_id)

        case = CaseSpec(
            case_id=case_id,
            runs_repo_name=runs_repo_name,
            label=label,
            repo=repo_spec,
        )

        cases.append(SuiteCase(case=case, overrides=SuiteCaseOverrides()))
        print(f"  ✅ Added case: {case.case_id} ({label})")

    if not cases:
        raise SystemExit("Suite mode requires at least one case.")

    return SuiteDefinition(
        suite_id=suite_id,
        scanners=scanners,
        cases=cases,
        analysis=analysis,
    )


def _write_suite_py(path: str | Path, suite_def: SuiteDefinition) -> Path:
    """Write a suite definition as a Python file exporting SUITE_RAW.

    This is intended as a *replay button* and provenance.

    Important: the output must be valid Python (True/False/None), so we use
    :func:`pprint.pformat` instead of JSON.

    The suite loader accepts either:
      - SUITE_DEF (SuiteDefinition)
      - SUITE_RAW (dict)

    We export SUITE_RAW to keep the file stable and decoupled from internal
    import paths.
    """
    p = Path(path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)

    raw = suite_def.to_dict()
    raw_py = pprint.pformat(raw, indent=2, sort_dicts=True)

    content = (
        "# GENERATED REPLAY FILE (interactive suite snapshot)\n"
        "#\n"
        "# Purpose:\n"
        "#   Replay an interactively curated suite later without re-answering prompts.\n"
        "#\n"
        "# How to replay:\n"
        "#   python sast_cli.py --mode suite --suite-file <this_file> --suite-id <new_suite_id>\n"
        "#\n"
        "# Notes:\n"
        "#   - If you built the suite from --worktrees-root or --cases-from, you usually do NOT need\n"
        "#     a replay file. Just rerun the same command.\n"
        "#   - This file exports SUITE_RAW (a dict). The loader converts it to a SuiteDefinition.\n"
        "#\n\n"
        f"SUITE_RAW = {raw_py}\n"
    )

    p.write_text(content, encoding="utf-8")
    return p


def _resolve_suite_case_for_run(sc: SuiteCase, *, repo_registry: Dict[str, Dict[str, str]]) -> Tuple[SuiteCase, str]:
    """Legacy shim.

    Suite-mode resolution now happens through the explicit resolver boundary
    (:func:`pipeline.suites.suite_resolver.resolve_suite_run`). This helper remains as
    a thin adapter for older codepaths/experiments.
    """
    from pipeline.suites.suite_resolver import resolve_suite_case

    return resolve_suite_case(sc, repo_registry=repo_registry)


def _build_suite_from_sources(args: argparse.Namespace) -> SuiteDefinition:
    """Build a suite definition without interactive prompts.

    Sources:
      - --cases-from CSV
      - --worktrees-root folder

    This is meant for prototype automation and CI.
    """
    suite_id = str(args.suite_id) if args.suite_id else new_suite_id()

    scanners_csv = args.scanners or DEFAULT_SCANNERS_CSV
    scanners = _parse_scanners_str(scanners_csv)
    if not scanners:
        raise SystemExit("No valid scanners selected.")

    analysis = SuiteAnalysisDefaults(
        skip=bool(args.skip_analysis),
        tolerance=int(args.tolerance),
        filter=str(args.analysis_filter),
    )

    cases: list[SuiteCase] = []
    seen: set[str] = set()

    if args.cases_from:
        loaded = _load_suite_cases_from_csv(Path(args.cases_from))
        for sc in loaded:
            cid = safe_name(sc.case.case_id)
            if cid in seen:
                continue
            c = sc.case
            if cid != c.case_id:
                sc = SuiteCase(case=CaseSpec(**{**c.__dict__, 'case_id': cid}), overrides=sc.overrides)
            cases.append(sc)
            seen.add(cid)

    if args.worktrees_root:
        loaded = _load_suite_cases_from_worktrees_root(Path(args.worktrees_root))
        for sc in loaded:
            cid = safe_name(sc.case.case_id)
            if cid in seen:
                continue
            cases.append(sc)
            seen.add(cid)

    if args.max_cases is not None:
        cases = cases[: int(args.max_cases)]

    if not cases:
        raise SystemExit("Suite mode requires at least one case (no cases loaded).")

    return SuiteDefinition(
        suite_id=suite_id,
        scanners=scanners,
        cases=cases,
        analysis=analysis,
    )


def run_suite_mode(args: argparse.Namespace, pipeline: SASTBenchmarkPipeline, *, repo_registry: Dict[str, Dict[str, str]]) -> int:
    """Run multiple cases under one suite id.

    Suite definitions are Python-only at runtime:
    - If --suite-file is provided, it must be a .py file exporting SUITE_DEF.
    - Otherwise we prompt interactively.
    """

    if args.no_suite:
        print("❌ Suite mode requires suite layout (do not use --no-suite).")
        return 2

    # Keep suite_root anchored under the repo root unless the user passed an
    # absolute path. This prevents "worked on my laptop" path drift when the
    # CLI is invoked from different working directories.
    suite_root = anchor_under_repo_root(Path(args.suite_root).expanduser())

    # Load or build suite definition
    # Load suite definition (Python only at runtime; YAML is migration-only)
    if args.suite_file:
        p = Path(args.suite_file).expanduser().resolve()
        if p.suffix.lower() in (".yaml", ".yml"):
            raise SystemExit(
                f"YAML suite definitions are no longer allowed at runtime: {p}\n"
                "Use scripts/migrate_suite_yaml_to_py.py to convert to a .py suite file."
            )
        suite_def = load_suite_py(p)
    else:
        if args.cases_from or args.worktrees_root:
            suite_def = _build_suite_from_sources(args)
        else:
            suite_def = _build_suite_interactively(args, repo_registry=repo_registry)

    # CLI overrides
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

    suite_dir = (suite_root / safe_name(suite_id)).resolve()
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
            (not args.suite_file)
            and (not args.cases_from)
            and (not args.worktrees_root)
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
        suite_root=suite_root,
        scanners=scanners,
        analysis=analysis_defaults,
        provenance=prov,
        repo_registry=repo_registry,
        ensure_dirs=True,
    )

    # Use the canonical, sanitized identifiers from the resolver.
    suite_id = resolved_run.suite_id
    suite_dir = resolved_run.suite_dir

    # If the user built this suite interactively, optionally write a Python replay file for reruns.
    #
    # If the suite came from --worktrees-root or --cases-from, the CLI command itself is already
    # replayable, so don't prompt by default.
    if prov.built_interactively:
        if _prompt_yes_no(
            "Save a replay file for this interactive suite? (rerun later without prompts)",
            default=False,
        ):
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

    print("\n🚀 Running suite")
    print(f"  Suite id : {suite_id}")
    print(f"  Suite dir: {suite_dir}")
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
            skip_analysis=bool(args.skip_analysis),
            tolerance=int(args.tolerance),
            analysis_filter=str(args.analysis_filter),
            sonar_project_key=sc.overrides.sonar_project_key or args.sonar_project_key,
            aikido_git_ref=sc.overrides.aikido_git_ref or args.aikido_git_ref,
            argv=list(sys.argv),
            python_executable=sys.executable,
        )

        rc_code = int(pipeline.run(req))
        overall = max(overall, rc_code)

    print("\n✅ Suite complete")
    print(f"  Suite id : {suite_id}")
    print(f"  Suite dir: {suite_dir}")
    return overall
