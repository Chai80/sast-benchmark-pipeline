from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Optional, Tuple

from cli.common import derive_runs_repo_name
from cli.ui import choose_from_menu
from cli.commands.analyze import run_analyze, run_analyze_suite_all_cases
from cli.commands.compare_suites import run_suite_compare
from cli.commands.benchmark import run_benchmark
from cli.commands.scan import run_scan
from cli.commands.suite import run_suite_mode
from cli.utils.suite_picker import prompt_for_suite, resolve_latest_suite_dir

from pipeline.identifiers import repo_id_from_repo_url, sanitize_sonar_key_fragment
from pipeline.models import CaseSpec, RepoSpec
from pipeline.pipeline import SASTBenchmarkPipeline


def _infer_suite_id_from_case_path(case_path: str) -> Optional[str]:
    """Best-effort: infer suite_id from a v2 case path.

    Expected shape:
      runs/suites/<suite_id>/cases/<case_id>
    """
    try:
        p = Path(case_path).resolve()
    except Exception:
        return None
    # .../runs/suites/<suite_id>/cases/<case_id>
    if p.parent.name == "cases":
        return p.parent.parent.name
    return None


def _choose_case_id_from_suite_dir(suite_dir: Path) -> str:
    cases_dir = suite_dir / "cases"
    if not cases_dir.exists():
        raise SystemExit(f"Suite has no cases directory: {cases_dir}")
    case_dirs = [p for p in cases_dir.iterdir() if p.is_dir()]
    case_dirs.sort(key=lambda x: x.name)
    if not case_dirs:
        raise SystemExit(f"No cases found in suite: {suite_dir}")

    return choose_from_menu("Choose a case:", {p.name: p.name for p in case_dirs})


def resolve_repo(
    args: argparse.Namespace,
    *,
    repo_registry: Dict[str, Dict[str, str]],
) -> Tuple[Optional[str], Optional[str], str, str]:
    """Return (repo_url, repo_path, label, repo_id)."""
    if args.repo_key:
        entry = repo_registry[args.repo_key]
        return entry.get("repo_url"), None, entry.get("label", args.repo_key), args.repo_key

    if args.repo_path:
        p = Path(args.repo_path).resolve()
        rid = sanitize_sonar_key_fragment(p.name)
        return args.repo_url, str(p), p.name, rid

    if args.repo_url:
        rid = repo_id_from_repo_url(args.repo_url)
        return args.repo_url, None, args.repo_url, rid

    choice = choose_from_menu(
        "Choose a repo source:",
        {
            "preset": "Pick from preset repos",
            "custom_url": "Enter a custom repo URL",
            "local_path": "Use a local repo path",
        },
    )

    if choice == "preset":
        key = choose_from_menu("Choose a preset repo:", {k: v["label"] for k, v in repo_registry.items()})
        entry = repo_registry[key]
        return entry.get("repo_url"), None, entry.get("label", key), key

    if choice == "custom_url":
        while True:
            url = input("Enter full repo URL (https://... .git or git@...): ").strip()
            if url.startswith(("https://", "http://", "git@")):
                rid = repo_id_from_repo_url(url)
                return url, None, url, rid
            print("That doesn't look like a git URL. Try again.")

    # local_path
    while True:
        path = input("Enter local repo path: ").strip()
        if path:
            p = Path(path).resolve()
            rid = sanitize_sonar_key_fragment(p.name)
            return None, str(p), p.name, rid
        print("Empty path. Try again.")


def dispatch(
    args: argparse.Namespace,
    pipeline: SASTBenchmarkPipeline,
    *,
    repo_registry: Dict[str, Dict[str, str]],
) -> int:
    # mode selection
    mode = args.mode
    if mode is None:
        if getattr(args, "suite_file", None):
            mode = "suite"
        elif args.scanner or args.repo_key or args.repo_url or args.repo_path:
            mode = "scan"
        else:
            mode = choose_from_menu(
                "Choose an action:",
                {
                    "scan": "Scan a repo with a single tool",
                    "benchmark": "Run multiple scanners on a repo",
                    "suite": "Run a multi-case suite (optional YAML)",
                    "analyze": "Analyze existing normalized runs (metrics)",
                    "import": "Import legacy runs/<tool>/... into suite layout",
                },
            )

    # Suite mode is a multi-case orchestrator. It does not have a single repo
    # target, so handle it before resolve_repo(...).
    if mode == "suite":
        return int(run_suite_mode(args, pipeline, repo_registry=repo_registry))

    # Import mode: convert legacy runs/<tool>/... into suite layout.
    # This is a filesystem operation and should never prompt for repo selection.
    if mode == "import":
        from cli.commands.import_legacy import run_import_legacy

        return int(run_import_legacy(args, pipeline, repo_registry=repo_registry))

    # Analyze mode operates on existing filesystem artifacts. It should not
    # prompt for a repo source unless the user is explicitly scanning.
    if mode == "analyze":
        suite_root = Path(args.suite_root).expanduser().resolve()

        # Suite-to-suite drift comparison is an analysis-only operation.
        # Handle it early to avoid any interactive prompts.
        metric = str(getattr(args, "metric", None) or "hotspots").strip()
        if metric == "suite_compare":
            return int(run_suite_compare(args, suite_root=suite_root))

        # If analyzing an explicit case directory, never prompt. Also infer
        # suite_id when possible so exports are not polluted.
        suite_id = str(args.suite_id) if args.suite_id else None
        if getattr(args, "case_path", None):
            suite_id = suite_id or _infer_suite_id_from_case_path(str(args.case_path))
            case_id = args.case_id or Path(str(args.case_path)).resolve().name
        else:
            metric = str(getattr(args, "metric", None) or "hotspots").strip()

            # No --case-path: resolve the suite directory.
            if suite_id is None:
                # Default (deterministic): analyze the suite referenced by runs/suites/LATEST,
                # with a lexicographic fallback when the pointer is missing.
                latest = resolve_latest_suite_dir(suite_root)
                if latest is None:
                    raise SystemExit(
                        f"No suites found under {suite_root}. "
                        "Run a suite/benchmark first, or pass --suite-id <suite_id>."
                    )

                suite_dir = latest
                suite_id = latest.name

                src = "LATEST" if (suite_root / "LATEST").exists() else "lexicographic fallback"
                print(f"ℹ️  Using suite: {suite_id} (default via {src})")
            else:
                # Allow explicit --suite-id latest.
                if suite_id.strip().lower() == "latest":
                    latest = resolve_latest_suite_dir(suite_root)
                    if latest is None:
                        raise SystemExit(f"No suites found under {suite_root} (LATEST not available).")
                    suite_dir = latest
                    suite_id = latest.name
                    print(f"ℹ️  Resolved --suite-id latest -> {suite_id}")
                else:
                    suite_dir = (suite_root / suite_id).resolve()
                    print(f"ℹ️  Using suite: {suite_id} (explicit)")

            if not Path(suite_dir).exists():

                raise SystemExit(

                    f"Suite '{suite_id}' not found under {suite_root}. "

                    f"Hint: omit --suite-id to use LATEST, or pass --suite-id latest."

                )


            # New default: when analyzing a suite, analyze ALL cases unless the
            # user pins --case-id.
            if metric == "suite" and not getattr(args, "case_id", None):
                return int(
                    run_analyze_suite_all_cases(
                        args,
                        pipeline,
                        suite_root=suite_root,
                        suite_id=str(suite_id),
                        suite_dir=suite_dir,
                    )
                )

            case_id = args.case_id or _choose_case_id_from_suite_dir(suite_dir)

        # In analyze mode, repo_name is only used as a label in analysis outputs.
        # Use the case_id unless the user explicitly provided a runs_repo_name.
        runs_repo_name = args.runs_repo_name or case_id
        label = runs_repo_name
        repo_spec = RepoSpec(repo_key=None, repo_url=None, repo_path=None)
        case = CaseSpec(
            case_id=case_id,
            runs_repo_name=runs_repo_name,
            label=label,
            repo=repo_spec,
            track=str(args.track).strip() if args.track else None,
        )

        return int(run_analyze(args, pipeline, case=case, suite_root=suite_root, suite_id=suite_id))

    repo_url, repo_path, label, repo_id = resolve_repo(args, repo_registry=repo_registry)

    # Derive the repo folder name used under runs/<tool>/<repo_name>/
    runs_repo_name = args.runs_repo_name or derive_runs_repo_name(
        repo_url=repo_url,
        repo_path=repo_path,
        fallback=label,
    )

    # Case identifier inside a suite. Defaults to the derived repo name, but can
    # be overridden for branch-per-case micro-suites.
    case_id = args.case_id or runs_repo_name

    repo_spec = RepoSpec(repo_key=args.repo_key, repo_url=repo_url, repo_path=repo_path)
    case = CaseSpec(
        case_id=case_id,
        runs_repo_name=runs_repo_name,
        label=label,
        repo=repo_spec,
        track=str(args.track).strip() if args.track else None,
    )

    suite_root = Path(args.suite_root).expanduser().resolve()
    suite_id = str(args.suite_id) if args.suite_id else None

    if mode == "scan":
        return int(run_scan(args, pipeline, case=case, repo_id=repo_id, suite_root=suite_root, suite_id=suite_id))

    # default: benchmark
    return int(run_benchmark(args, pipeline, case=case, repo_id=repo_id, suite_root=suite_root, suite_id=suite_id))
