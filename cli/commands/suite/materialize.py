from __future__ import annotations

import argparse
import pprint
from pathlib import Path
from typing import Dict, List, Tuple

from cli.common import derive_runs_repo_name, parse_csv
from cli.suite_sources import (
    _bootstrap_worktrees_from_repo_url,
    _case_id_from_pathlike,
    _discover_git_checkouts_under,
    _load_suite_cases_from_csv,
    _load_suite_cases_from_worktrees_root,
    _parse_branches_spec,
    _resolve_repo_for_suite_case_interactive,
    _suite_case_from_repo_path,
)

from cli.ui import choose_from_menu, _parse_index_selection, _prompt_text
from pipeline.core import ROOT_DIR as PIPELINE_ROOT_DIR, repo_id_from_repo_url
from pipeline.models import CaseSpec
from pipeline.scanners import DEFAULT_SCANNERS_CSV, SUPPORTED_SCANNERS
from pipeline.suites.bundles import anchor_under_repo_root, safe_name
from pipeline.suites.layout import new_suite_id
from pipeline.suites.suite_definition import (
    SuiteAnalysisDefaults,
    SuiteCase,
    SuiteCaseOverrides,
    SuiteDefinition,
)


ROOT_DIR = PIPELINE_ROOT_DIR


def _add_cases_from_worktrees_root_interactively(
    root: Path,
    *,
    cases: List[SuiteCase],
    seen_case_ids: set[str],
    default_select: str = "all",
) -> int:
    """Discover git checkouts under a worktrees root and add them as suite cases.

    This powers both:
      - "Add cases from local worktrees" (already cloned)
      - "Bootstrap worktrees from repo URL + branches" (clone + add cases)

    Notes
    -----
    - Excludes a top-level '_base' clone (used as the worktree anchor).
    - Prompts the user to select which worktrees to include.
    """

    root = Path(root).expanduser().resolve()
    discovered = _discover_git_checkouts_under(root)

    # Filter out the base clone used to anchor worktrees.
    repos: list[Path] = []
    rels: list[str] = []
    for repo_dir in discovered:
        try:
            rel = repo_dir.relative_to(root).as_posix()
        except Exception:
            rel = repo_dir.name
        if repo_dir.name == "_base" or rel == "_base":
            continue
        repos.append(repo_dir)
        rels.append(rel)

    if not repos:
        print(f"  ❌ No git checkouts found under: {root}")
        return 0

    print("\nDiscovered worktrees:")
    for i, rel in enumerate(rels, start=1):
        print(f"[{i}] {rel}")

    raw_sel = _prompt_text(
        "Select worktrees by number (e.g., 1,3-5) or 'all'", default=default_select
    )
    sel = _parse_index_selection(raw_sel, n=len(rels))
    if not sel:
        print("  ⚠️  No worktrees selected.")
        return 0

    added = 0
    for i in sel:
        rel = rels[i]
        repo_dir = repos[i]

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

    return added



def _parse_scanners_str(value: str) -> List[str]:
    raw = parse_csv(value)
    scanners = [t for t in raw if t in SUPPORTED_SCANNERS]
    unknown = [t for t in raw if t not in SUPPORTED_SCANNERS]
    if unknown:
        print(f"  ⚠️  ignoring unknown scanners: {', '.join(unknown)}")
    return scanners


def _build_suite_interactively(
    args: argparse.Namespace, *, repo_registry: Dict[str, Dict[str, str]]
) -> SuiteDefinition:
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
                "add": "Add a case (preset / URL auto-clone / local path)",
                "bootstrap_worktrees": "Bootstrap worktrees from repo URL + branches (clone + add cases)",
                "add_worktrees": "Add cases from local worktrees (already cloned)",
                "add_csv": "Add cases from CSV file (paths or URLs)",
                "done": "Finish suite definition",
            },
        )
        if action == "done":
            break

        if action == "bootstrap_worktrees":
            # Clone + materialize branch worktrees, then add as many cases as desired.
            repo_spec, label, _repo_id = _resolve_repo_for_suite_case_interactive(
                repo_registry=repo_registry
            )
            if not repo_spec.repo_url:
                print("  ❌ Worktree bootstrap requires a repo URL. Choose a preset or custom URL.")
                continue

            default_branches = "A01-A10" if "owasp" in str(label).lower() else "main"
            raw_branches = _prompt_text(
                "Branches to materialize (comma-separated; supports ranges like 'A01-A10')",
                default=default_branches,
            ).strip()
            branches = _parse_branches_spec(raw_branches)
            if not branches:
                print("  ❌ No branches provided.")
                continue

            default_root = ROOT_DIR / "repos" / "worktrees" / repo_id_from_repo_url(str(repo_spec.repo_url))
            root_in = _prompt_text("Worktrees root folder", default=str(default_root)).strip()
            wt_root = anchor_under_repo_root(Path(root_in).expanduser())

            wt_root = _bootstrap_worktrees_from_repo_url(
                repo_url=str(repo_spec.repo_url),
                branches=branches,
                worktrees_root=wt_root,
            )
            print(f"🌿 Suite worktrees ready: {wt_root}")

            added = _add_cases_from_worktrees_root_interactively(
                wt_root, cases=cases, seen_case_ids=seen_case_ids
            )
            if added:
                print(f"  ✅ Added {added} case(s) from bootstrapped worktrees.")
            continue

        if action == "add_worktrees":
            # Discover git checkouts under repos/worktrees/<something> and add many cases at once.
            base = (ROOT_DIR / "repos" / "worktrees").resolve()
            root: Path
            if base.exists():
                candidates = [p for p in base.iterdir() if p.is_dir()]
            else:
                candidates = []

            if candidates:
                opts: Dict[str, object] = {
                    p.name: str(p) for p in sorted(candidates, key=lambda p: p.name)
                }
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

            added = _add_cases_from_worktrees_root_interactively(
                root, cases=cases, seen_case_ids=seen_case_ids
            )
            if added:
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
                    sc = SuiteCase(
                        case=CaseSpec(**{**c.__dict__, "case_id": cid}),
                        overrides=sc.overrides,
                    )
                cases.append(sc)
                seen_case_ids.add(cid)
                added += 1

            print(f"  ✅ Added {added} case(s) from CSV.")
            continue

        # Default: add a single case via preset/custom/local
        repo_spec, label, _repo_id = _resolve_repo_for_suite_case_interactive(
            repo_registry=repo_registry
        )

        runs_repo_name = derive_runs_repo_name(
            repo_url=repo_spec.repo_url,
            repo_path=repo_spec.repo_path,
            fallback=label,
        )

        proposed = runs_repo_name
        raw_case_id = (
            _prompt_text("Case id (folder + DB key)", default=proposed).strip() or proposed
        )
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
        if repo_spec.repo_url:
            print("  ℹ️  This case uses a repo URL; it will be cloned automatically during scanner execution.")

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


def _resolve_suite_case_for_run(
    sc: SuiteCase, *, repo_registry: Dict[str, Dict[str, str]]
) -> Tuple[SuiteCase, str]:
    """Legacy shim.

    Suite-mode resolution now happens through the explicit resolver boundary
    (:func:`pipeline.suites.suite_resolver.resolve_suite_run`). This helper
    remains as a thin adapter for older codepaths/experiments.
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
                sc = SuiteCase(
                    case=CaseSpec(**{**c.__dict__, "case_id": cid}),
                    overrides=sc.overrides,
                )
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
