from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Optional, Tuple

from cli.ui import choose_from_menu
from cli.commands.analyze import run_analyze
from cli.commands.benchmark import run_benchmark
from cli.commands.scan import run_scan
from cli.commands.suite import run_suite_mode

from pipeline.core import repo_id_from_repo_url, sanitize_sonar_key_fragment
from pipeline.models import CaseSpec, RepoSpec
from pipeline.pipeline import SASTBenchmarkPipeline


def _derive_runs_repo_name(*, repo_url: Optional[str], repo_path: Optional[str], fallback: str) -> str:
    """Best-effort repo name used by scanners under runs/<tool>/<repo_name>/..."""
    if repo_url:
        last = repo_url.rstrip("/").split("/")[-1]
        return last[:-4] if last.endswith(".git") else last
    if repo_path:
        return Path(repo_path).resolve().name
    return fallback


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
                },
            )

    # Suite mode is a multi-case orchestrator. It does not have a single repo
    # target, so handle it before resolve_repo(...).
    if mode == "suite":
        return int(run_suite_mode(args, pipeline, repo_registry=repo_registry))

    repo_url, repo_path, label, repo_id = resolve_repo(args, repo_registry=repo_registry)

    # Derive the repo folder name used under runs/<tool>/<repo_name>/
    runs_repo_name = args.runs_repo_name or _derive_runs_repo_name(
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

    suite_root = Path(args.bundle_root)
    suite_id = str(args.bundle_id) if args.bundle_id else None

    if mode == "analyze":
        return int(run_analyze(args, pipeline, case=case, suite_root=suite_root, suite_id=suite_id))

    if mode == "scan":
        return int(run_scan(args, pipeline, case=case, repo_id=repo_id, suite_root=suite_root, suite_id=suite_id))

    # default: benchmark
    return int(run_benchmark(args, pipeline, case=case, repo_id=repo_id, suite_root=suite_root, suite_id=suite_id))
