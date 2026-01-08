#!/usr/bin/env python3
"""sast_cli.py

Top-level CLI wrapper for the Durinn SAST benchmarking pipeline.

Modes
-----
1) scan
   - run one scanner against one repo
2) benchmark
   - run multiple scanners against one repo
   - (default) run the analysis suite after scans
3) suite
   - run multiple scanners across multiple cases (many repos / branches)
   - suite definitions can optionally be supplied as YAML (or built interactively)
4) analyze
   - compute cross-tool metrics from existing normalized runs

Suite layout (recommended)
--------------------------
By default this CLI writes *everything* for a run into a single **suite** folder
with one **case** folder per target:

  runs/suites/<suite_id>/
    cases/<case_id>/
      case.json
      tool_runs/<tool>/<run_id>/...
      analysis/...
      gt/...

This keeps the output tree readable and makes it easy to share a specific
experiment run (or rerun analysis) without hunting across many directories.

Use --case-id when you want an explicit case identifier (e.g., branch-per-case
micro-suites).

Examples
--------
# Benchmark Juice Shop into a new suite (then run analysis suite)
python sast_cli.py --mode benchmark --repo-key juice_shop --scanners semgrep,snyk,sonar

# Same, but pick a specific suite id
python sast_cli.py --mode benchmark --repo-key juice_shop --suite-id 20260104T013000Z

# Analyze the latest suite for a target
python sast_cli.py --mode analyze --metric suite --repo-key juice_shop --suite-id latest

# Legacy behavior (write directly to runs/<tool>/...)
python sast_cli.py --mode benchmark --repo-key juice_shop --no-suite

# Run a multi-case suite from a YAML definition (optional)
python sast_cli.py --mode suite --suite-file suites/example_suite.yaml
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pipeline.core import (
    ROOT_DIR as PIPELINE_ROOT_DIR,
    SUPPORTED_SCANNERS,
    repo_id_from_repo_url,
    sanitize_sonar_key_fragment,
)
from pipeline.bundles import safe_name
from pipeline.layout import new_suite_id
from pipeline.models import RepoSpec, CaseSpec
from pipeline.orchestrator import AnalyzeRequest, RunRequest, run_analyze, run_tools

from pipeline.suite_definition import (
    SuiteAnalysisDefaults,
    SuiteCase,
    SuiteCaseOverrides,
    SuiteDefinition,
    dump_suite_yaml,
    load_suite_yaml,
)


ROOT_DIR = PIPELINE_ROOT_DIR  # repo root
ENV_PATH = ROOT_DIR / ".env"

# Replace/add your preset repos here
REPOS: Dict[str, Dict[str, str]] = {
    "juice_shop": {"label": "Juice Shop", "repo_url": "https://github.com/juice-shop/juice-shop.git"},
    "webgoat": {"label": "WebGoat", "repo_url": "https://github.com/WebGoat/WebGoat.git"},
    "dvwa": {"label": "DVWA", "repo_url": "https://github.com/digininja/DVWA.git"},
    "owasp_benchmark": {"label": "OWASP BenchmarkJava", "repo_url": "https://github.com/OWASP/BenchmarkJava.git"},
}

SCANNER_LABELS: Dict[str, str] = {
    "semgrep": "Semgrep",
    "sonar": "SonarCloud",
    "snyk": "Snyk Code",
    "aikido": "Aikido",
}


# -------------------------------------------------------------------
# .env loader (no dependency)
# -------------------------------------------------------------------

def load_dotenv_if_present(dotenv_path: Path) -> None:
    """Minimal .env loader. Loads KEY=VALUE into os.environ if not already set."""
    if not dotenv_path.exists():
        return

    for raw in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, val = line.split("=", 1)
        key = key.strip()
        raw_val = val.strip()

        # Quoted value
        if (raw_val.startswith('"') and raw_val.endswith('"')) or (raw_val.startswith("'") and raw_val.endswith("'")):
            parsed_val = raw_val[1:-1]
        else:
            # Strip inline comments only when preceded by whitespace: "VALUE   # comment"
            parsed_val = re.split(r"\s+#", raw_val, maxsplit=1)[0].strip()
            parsed_val = parsed_val.strip('"').strip("'")

        parsed_val = parsed_val.replace("\r", "")
        if key and key not in os.environ:
            os.environ[key] = parsed_val


# -------------------------------------------------------------------
# Helper: select from a menu
# -------------------------------------------------------------------

def choose_from_menu(title: str, options: Dict[str, object]) -> str:
    """Show a 1..N menu of keys in 'options' and return the chosen key."""
    keys = list(options.keys())
    print("\n" + title)
    for idx, key in enumerate(keys, start=1):
        val = options[key]
        if isinstance(val, dict) and "label" in val:
            label = str(val["label"])
        else:
            label = str(val)
        print(f"[{idx}] {label} ({key})")

    while True:
        choice = input(f"Enter number (1-{len(keys)}) or Z to exit: ").strip()
        if not choice:
            print("Please enter a number or Z to exit.")
            continue
        if choice.upper() == "Z":
            print("Exiting (Z selected).")
            raise SystemExit(0)
        if choice.isdigit():
            n = int(choice)
            if 1 <= n <= len(keys):
                return keys[n - 1]
        print(f"Invalid choice. Please enter 1-{len(keys)} or Z.")


# -------------------------------------------------------------------
# Small parsing helpers
# -------------------------------------------------------------------

def _parse_csv(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def _derive_runs_repo_name(*, repo_url: Optional[str], repo_path: Optional[str], fallback: str) -> str:
    """Best-effort repo name used by scanners under runs/<tool>/<repo_name>/..."""
    if repo_url:
        last = repo_url.rstrip("/").split("/")[-1]
        return last[:-4] if last.endswith(".git") else last
    if repo_path:
        return Path(repo_path).resolve().name
    return fallback


# -------------------------------------------------------------------
# CLI args
# -------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Top-level CLI for SAST pipeline (Durinn).")

    parser.add_argument(
        "--mode",
        choices=["scan", "benchmark", "suite", "analyze"],
        help=(
            "scan = one tool, benchmark = multiple tools, suite = multi-case suite run (optional YAML), "
            "analyze = compute metrics from existing runs"
        ),
    )
    parser.add_argument(
        "--scanner",
        choices=sorted(SUPPORTED_SCANNERS),
        help="(scan mode) Which scanner to run",
    )
    parser.add_argument(
        "--scanners",
        help="(benchmark|suite mode) Comma-separated scanners (default: semgrep,snyk,sonar,aikido)",
    )

    parser.add_argument(
        "--track",
        type=str,
        default=None,
        help=(
            "Optional benchmark track to scope scoring/execution (e.g. sast|sca|iac|secrets). "
            "If omitted, scoring considers all GT tracks present in the repo."
        ),
    )

    # Suite layout
    parser.add_argument(
        "--suite-root",
        "--bundle-root",
        dest="bundle_root",
        default=str(ROOT_DIR / "runs" / "suites"),
        help="Base directory for suite runs (default: runs/suites).",
    )
    parser.add_argument(
        "--suite-id",
        "--bundle-id",
        dest="bundle_id",
        help=(
            "Suite run id to create/use. If omitted in scan/benchmark, a new UTC timestamp is used. "
            "In analyze mode you can pass 'latest'."
        ),
    )

    parser.add_argument(
        "--suite-file",
        dest="suite_file",
        help=(
            "(suite mode) Optional YAML suite definition. If omitted, you can build a suite interactively. "
            "This YAML is a *plan* (what you intend to run), while suite.json/case.json capture what actually ran."
        ),
    )

    parser.add_argument(
        "--case-id",
        dest="case_id",
        help=(
            "Override the case id within the suite (folder name under runs/suites/<suite_id>/cases/<case_id>/). "
            "If omitted, we derive it from the repo name. Useful for branch-per-case micro-suites."
        ),
    )
    parser.add_argument(
        "--case-path",
        "--bundle-path",
        dest="bundle_path",
        help="(analyze mode) Path to an existing case dir (overrides --suite-root/--suite-id).",
    )
    parser.add_argument(
        "--no-suite",
        "--no-bundle",
        dest="no_bundle",
        action="store_true",
        help="Disable suite layout and use legacy runs/<tool>/<repo>/<run_id>/... paths.",
    )
    parser.add_argument(
        "--skip-analysis",
        action="store_true",
        help="(benchmark|suite mode) Skip the analysis suite step (scans only).",
    )

    # Analysis / metrics
    parser.add_argument(
        "--metric",
        choices=["hotspots", "suite"],
        help="(analyze mode) Metric to compute (hotspots|suite)",
    )
    parser.add_argument(
        "--tools",
        help="(analyze mode) Comma-separated tools to include (default: semgrep,snyk,sonar,aikido)",
    )
    parser.add_argument(
        "--runs-dir",
        default=str(ROOT_DIR / "runs"),
        help="(analyze mode, legacy) Base runs directory (default: <repo_root>/runs)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="(analyze mode) Output format (default: text)",
    )
    parser.add_argument(
        "--out",
        help="(analyze mode) Optional output path to write the JSON report",
    )
    parser.add_argument(
        "--analysis-out-dir",
        help=(
            "(analyze mode, suite) Optional output directory for suite artifacts. "
            "If using suites, default is <case>/analysis/."
        ),
    )
    parser.add_argument(
        "--tolerance",
        type=int,
        default=3,
        help="(analysis suite) Line clustering tolerance for location matrix (default: 3)",
    )
    parser.add_argument(
        "--analysis-filter",
        choices=["security", "all"],
        default="security",
        help="(analysis suite) Finding filter mode (default: security)",
    )
    parser.add_argument(
        "--max-unique",
        type=int,
        default=25,
        help="(analyze hotspots) For text output, show up to N unique files per tool (default: 25)",
    )
    parser.add_argument(
        "--runs-repo-name",
        help=(
            "(analyze mode) Override the repo directory name under runs/<tool>/. "
            "By default we derive it from the repo URL (e.g., juice-shop) or local folder name."
        ),
    )

    # Repo selection
    parser.add_argument("--repo-key", choices=sorted(REPOS.keys()), help="Preset repo key (recommended)")
    parser.add_argument("--repo-url", help="Custom git repo URL")
    parser.add_argument("--repo-path", help="Local repo path (skip clone)")

    # Sonar-specific
    parser.add_argument(
        "--sonar-project-key",
        help="(sonar only) Override SonarCloud project key. If omitted, we derive ORG_<repo_id>.",
    )
    # Aikido-specific
    parser.add_argument(
        "--aikido-git-ref",
        help=(
            "(aikido only) Override the git reference passed to scan_aikido.py as --git-ref. "
            "Use this when running aikido with --repo-path and no --repo-url (e.g., suite branch clones/worktrees). "
            "Example: Chai80/durinn-owasp2021-python-micro-suite"
        ),
    )

    parser.add_argument("--dry-run", action="store_true", help="Print commands but do not execute")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress scanner stdout/stderr (not recommended for debugging)",
    )

    return parser.parse_args()


# -------------------------------------------------------------------
# Repo resolution
# -------------------------------------------------------------------

def resolve_repo(args: argparse.Namespace) -> Tuple[Optional[str], Optional[str], str, str]:
    """Return (repo_url, repo_path, label, repo_id)."""
    if args.repo_key:
        entry = REPOS[args.repo_key]
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
        key = choose_from_menu("Choose a preset repo:", {k: v["label"] for k, v in REPOS.items()})
        entry = REPOS[key]
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


# -------------------------------------------------------------------
# Suite mode (optional YAML)
# -------------------------------------------------------------------

def _prompt_text(prompt: str, default: Optional[str] = None) -> str:
    """Prompt for free-text input with an optional default."""
    if default is not None:
        raw = input(f"{prompt} [{default}]: ").strip()
        return raw or str(default)
    return input(f"{prompt}: ").strip()


def _prompt_yes_no(prompt: str, *, default: bool = False) -> bool:
    """Prompt for a yes/no question."""
    suffix = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{prompt} ({suffix}): ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes"}:
            return True
        if raw in {"n", "no"}:
            return False
        print("Please enter y or n.")


def _parse_scanners_str(value: str) -> List[str]:
    raw = _parse_csv(value)
    scanners = [t for t in raw if t in SUPPORTED_SCANNERS]
    unknown = [t for t in raw if t not in SUPPORTED_SCANNERS]
    if unknown:
        print(f"  ⚠️  ignoring unknown scanners: {', '.join(unknown)}")
    return scanners


def _resolve_repo_for_suite_case_interactive() -> Tuple[RepoSpec, str, str]:
    """Resolve a repo target for *one* suite case.

    Returns (repo_spec, label, repo_id).
    """
    source = choose_from_menu(
        "Choose a repo source for this case:",
        {
            "preset": "Pick from preset repos",
            "custom_url": "Enter a custom repo URL",
            "local_path": "Use a local repo path",
        },
    )

    if source == "preset":
        key = choose_from_menu("Choose a preset repo:", {k: v["label"] for k, v in REPOS.items()})
        entry = REPOS[key]
        repo_url = entry.get("repo_url")
        label = entry.get("label", key)
        return RepoSpec(repo_key=key, repo_url=repo_url, repo_path=None), label, key

    if source == "custom_url":
        while True:
            url = input("Enter full repo URL (https://... .git or git@...): ").strip()
            if url.startswith(("https://", "http://", "git@")):
                rid = repo_id_from_repo_url(url)
                return RepoSpec(repo_key=None, repo_url=url, repo_path=None), url, rid
            print("That doesn't look like a git URL. Try again.")

    # local_path
    while True:
        path = input("Enter local repo path: ").strip()
        if path:
            p = Path(path).resolve()
            rid = sanitize_sonar_key_fragment(p.name)
            return RepoSpec(repo_key=None, repo_url=None, repo_path=str(p)), p.name, rid
        print("Empty path. Try again.")


def _build_suite_interactively(args: argparse.Namespace) -> SuiteDefinition:
    print("\n🧩 Suite mode: run multiple cases under one suite id.")
    print("   - Use this for scanning many repos or many branches/worktrees.")
    print("   - YAML is optional; suite.json/case.json/run.json are always written.\n")

    suite_id_in = _prompt_text("Suite id (press Enter to auto-generate)", default="").strip()
    suite_id = suite_id_in or new_suite_id()

    default_scanners_csv = args.scanners or "semgrep,snyk,sonar,aikido"
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
                "done": "Finish suite definition",
            },
        )
        if action == "done":
            break

        repo_spec, label, _repo_id = _resolve_repo_for_suite_case_interactive()

        runs_repo_name = _derive_runs_repo_name(
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


def _resolve_suite_case_for_run(sc: SuiteCase) -> Tuple[SuiteCase, str]:
    """Resolve repo_key -> repo_url and compute a stable repo_id for the run."""
    c = sc.case
    repo_key = c.repo.repo_key
    repo_url = c.repo.repo_url
    repo_path = c.repo.repo_path
    label = c.label

    # Resolve repo_key -> repo_url via presets (for now). In the future this
    # will use a repos registry file.
    if repo_key and not repo_url and not repo_path:
        if repo_key not in REPOS:
            raise SystemExit(
                f"Suite case '{c.case_id}' uses repo_key='{repo_key}' but it isn't known. "
                "Use repo_url/repo_path or add the key to REPOS."
            )
        entry = REPOS[repo_key]
        repo_url = entry.get("repo_url")
        label = entry.get("label", label)

    if not repo_url and not repo_path:
        raise SystemExit(
            f"Suite case '{c.case_id}' must specify one of repo_url, repo_path, or a resolvable repo_key."
        )

    # Improve runs_repo_name if YAML omitted it (common).
    derived_runs_name = _derive_runs_repo_name(repo_url=repo_url, repo_path=repo_path, fallback=c.case_id)
    runs_repo_name = c.runs_repo_name
    if not runs_repo_name or runs_repo_name == c.case_id:
        runs_repo_name = derived_runs_name

    # Compute repo_id (used for Sonar project key derivation).
    if repo_key:
        repo_id = repo_key
    elif repo_url:
        repo_id = repo_id_from_repo_url(repo_url)
    else:
        repo_id = sanitize_sonar_key_fragment(Path(repo_path).resolve().name)

    case_id = safe_name(c.case_id)
    if case_id != c.case_id:
        print(f"  ⚠️  case_id '{c.case_id}' sanitized to '{case_id}'")

    resolved = CaseSpec(
        case_id=case_id,
        runs_repo_name=runs_repo_name,
        label=label,
        repo=RepoSpec(repo_key=repo_key, repo_url=repo_url, repo_path=repo_path),
        branch=c.branch,
        commit=c.commit,
        track=c.track,
        tags=c.tags or {},
    )

    return SuiteCase(case=resolved, overrides=sc.overrides), repo_id


def run_suite_mode(args: argparse.Namespace) -> int:
    """Run multiple cases under one suite id.

    YAML is optional:
    - If --suite-file is provided, we load it.
    - Otherwise we prompt interactively.
    """

    if args.no_bundle:
        print("❌ Suite mode requires suite layout (do not use --no-suite).")
        return 2

    suite_root = Path(args.bundle_root)

    # Load or build suite definition
    suite_def = load_suite_yaml(args.suite_file) if args.suite_file else _build_suite_interactively(args)

    # CLI overrides
    suite_id = str(args.bundle_id) if args.bundle_id else (suite_def.suite_id or new_suite_id())

    scanners: List[str]
    if args.scanners:
        scanners = _parse_scanners_str(args.scanners)
    elif suite_def.scanners:
        scanners = [t for t in suite_def.scanners if t in SUPPORTED_SCANNERS]
    else:
        scanners = ["semgrep", "snyk", "sonar", "aikido"]

    if not scanners:
        raise SystemExit("No valid scanners specified for suite mode.")

    # If suite YAML is present, let it drive analysis defaults; otherwise use CLI.
    if args.suite_file:
        tolerance = int(suite_def.analysis.tolerance)
        analysis_filter = str(suite_def.analysis.filter)
        skip_analysis = bool(args.skip_analysis) or bool(suite_def.analysis.skip)
    else:
        tolerance = int(args.tolerance)
        analysis_filter = str(args.analysis_filter)
        skip_analysis = bool(args.skip_analysis)

    # Resolve and validate cases
    resolved_cases: List[Tuple[SuiteCase, str]] = []
    seen: set[str] = set()
    for sc in suite_def.cases:
        resolved, repo_id = _resolve_suite_case_for_run(sc)
        if resolved.case.case_id in seen:
            raise SystemExit(f"Duplicate case_id in suite: {resolved.case.case_id}")
        seen.add(resolved.case.case_id)
        resolved_cases.append((resolved, repo_id))

    suite_dir = suite_root / safe_name(suite_id)
    suite_dir.mkdir(parents=True, exist_ok=True)

    # If user provided a YAML file, copy it into the suite folder for provenance.
    if args.suite_file:
        try:
            src = Path(args.suite_file).expanduser().resolve()
            dst = suite_dir / "suite_input.yaml"
            if src != dst:
                shutil.copyfile(src, dst)
        except Exception:
            # best-effort only
            pass

    # If suite was built interactively, optionally write a YAML plan for reruns.
    if not args.suite_file:
        if _prompt_yes_no("Save this suite definition to a YAML file for reruns?", default=False):
            default_out = suite_dir / "suite_definition.yaml"
            out_path = _prompt_text("YAML output path", default=str(default_out)).strip() or str(default_out)
            # Dump a normalized/clean definition (resolved IDs/scanners/analysis)
            to_write = SuiteDefinition(
                suite_id=suite_id,
                scanners=scanners,
                cases=[sc for sc, _ in resolved_cases],
                analysis=SuiteAnalysisDefaults(skip=skip_analysis, tolerance=tolerance, filter=analysis_filter),
            )
            try:
                written = dump_suite_yaml(out_path, to_write)
                print(f"  ✅ Wrote suite definition: {written}")
            except Exception as e:
                print(f"  ⚠️  Failed to write suite definition YAML: {e}")

    print("\n🚀 Running suite")
    print(f"  Suite id : {suite_id}")
    print(f"  Suite dir: {suite_dir}")
    print(f"  Cases    : {len(resolved_cases)}")
    print(f"  Scanners : {', '.join(scanners)}")

    overall = 0
    for idx, (sc, repo_id) in enumerate(resolved_cases, start=1):
        case = sc.case
        print("\n" + "=" * 72)
        print(f"🧪 Case {idx}/{len(resolved_cases)}: {case.case_id} ({case.label})")
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
            analysis_filter=str(analysis_filter),
            sonar_project_key=sc.overrides.sonar_project_key or args.sonar_project_key,
            aikido_git_ref=sc.overrides.aikido_git_ref or args.aikido_git_ref,
            argv=list(sys.argv),
            python_executable=sys.executable,
        )

        rc = int(run_tools(req))
        overall = max(overall, rc)

    print("\n✅ Suite complete")
    print(f"  Suite id : {suite_id}")
    print(f"  Suite dir: {suite_dir}")
    return overall


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main() -> None:
    load_dotenv_if_present(ENV_PATH)
    args = parse_args()

    # mode selection
    mode = args.mode
    if mode is None:
        if args.suite_file:
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
        raise SystemExit(run_suite_mode(args))

    repo_url, repo_path, label, repo_id = resolve_repo(args)

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

    # ------------------- ANALYZE MODE ------------------
    if mode == "analyze":
        metric = args.metric or "hotspots"

        tools_csv = args.tools or "snyk,semgrep,sonar,aikido"
        tools = [t for t in _parse_csv(tools_csv) if t in SUPPORTED_SCANNERS]

        req = AnalyzeRequest(
            metric=metric,
            case=case,
            suite_root=suite_root,
            suite_id=suite_id,
            case_path=args.bundle_path,
            runs_dir=Path(args.runs_dir),
            tools=tools,
            output_format=str(args.format),
            out=args.out,
            analysis_out_dir=args.analysis_out_dir,
            tolerance=int(args.tolerance),
            analysis_filter=str(args.analysis_filter),
            max_unique=int(args.max_unique),
        )
        raise SystemExit(run_analyze(req))

    # --------------------- SCAN MODE ---------------------
    if mode == "scan":
        scanner = args.scanner
        if scanner is None:
            scanner = choose_from_menu(
                "Choose a scanner:",
                {k: SCANNER_LABELS.get(k, k) for k in sorted(SUPPORTED_SCANNERS)},
            )

        req = RunRequest(
            invocation_mode="scan",
            case=case,
            repo_id=repo_id,
            scanners=[scanner],
            suite_root=suite_root,
            suite_id=suite_id,
            use_suite=not bool(args.no_bundle),
            dry_run=bool(args.dry_run),
            quiet=bool(args.quiet),
            # scan mode never runs analysis
            skip_analysis=True,
            tolerance=int(args.tolerance),
            analysis_filter=str(args.analysis_filter),
            sonar_project_key=args.sonar_project_key,
            aikido_git_ref=args.aikido_git_ref,
            argv=list(sys.argv),
            python_executable=sys.executable,
        )
        raise SystemExit(run_tools(req))

    # ------------------- BENCHMARK MODE ------------------
    scanners_arg = args.scanners or "semgrep,snyk,sonar,aikido"
    scanners = [s for s in _parse_csv(scanners_arg) if s in SUPPORTED_SCANNERS]
    if not scanners:
        raise SystemExit("No valid scanners specified for benchmark mode.")

    req = RunRequest(
        invocation_mode="benchmark",
        case=case,
        repo_id=repo_id,
        scanners=scanners,
        suite_root=suite_root,
        suite_id=suite_id,
        use_suite=not bool(args.no_bundle),
        dry_run=bool(args.dry_run),
        quiet=bool(args.quiet),
        skip_analysis=bool(args.skip_analysis),
        tolerance=int(args.tolerance),
        analysis_filter=str(args.analysis_filter),
        sonar_project_key=args.sonar_project_key,
        aikido_git_ref=args.aikido_git_ref,
        argv=list(sys.argv),
        python_executable=sys.executable,
    )

    raise SystemExit(run_tools(req))


if __name__ == "__main__":
    main()
