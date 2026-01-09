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
   - suite definitions are supplied as Python (.py) (or built interactively)
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

# Run a multi-case suite from a Python definition
python sast_cli.py --mode suite --suite-file suites/example_suite.py
"""

from __future__ import annotations

import argparse
import csv
import json
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
from pipeline.bundles import anchor_under_repo_root, safe_name
from pipeline.layout import new_suite_id
from pipeline.models import RepoSpec, CaseSpec
from pipeline.orchestrator import AnalyzeRequest, RunRequest
from pipeline.pipeline import SASTBenchmarkPipeline
from pipeline.wiring import build_pipeline

from pipeline.suite_definition import (
    SuiteAnalysisDefaults,
    SuiteCase,
    SuiteCaseOverrides,
    SuiteDefinition,
)

from pipeline.suite_py_loader import load_suite_py

from pipeline.suite_resolver import SuiteInputProvenance, resolve_suite_run


ROOT_DIR = PIPELINE_ROOT_DIR  # repo root

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
            "(suite mode) Optional Python suite definition (.py exporting SUITE_DEF). If omitted, you can build a suite interactively "
            "or use --cases-from / --worktrees-root to load many cases quickly. "
            "suite.json/case.json/run.json are always written as the ground-truth record of what actually ran."
        ),
    )

    parser.add_argument(
        "--cases-from",
        dest="cases_from",
        help=(
            "(suite mode) Load cases from a CSV file (columns: case_id,repo_path[,label][,branch][,track][,tags_json]). "
            "Useful for branch-per-case micro-suites and CI runs."
        ),
    )

    parser.add_argument(
        "--worktrees-root",
        dest="worktrees_root",
        help=(
            "(suite mode) Import cases by discovering git worktrees/checkouts under this folder. "
            "Each git checkout becomes one case. Example: repos/worktrees/durinn-owasp2021-python-micro-suite"
        ),
    )

    parser.add_argument(
        "--max-cases",
        dest="max_cases",
        type=int,
        default=None,
        help="(suite mode) When loading cases from --cases-from/--worktrees-root, only include the first N cases.",
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
# Suite mode (Python suite file / interactive / CSV / worktrees)
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




def _parse_index_selection(raw: str, *, n: int) -> List[int]:
    """Parse a user selection like: 'all' or '1,3-5' into 0-based indices."""
    s = (raw or '').strip().lower()
    if not s:
        return []
    if s in {'all', '*'}:
        return list(range(n))

    out: set[int] = set()
    parts = re.split(r"[\s,]+", s)
    for part in parts:
        if not part:
            continue
        if part in {'z', 'quit', 'exit'}:
            raise SystemExit(0)
        if '-' in part:
            a, b = part.split('-', 1)
            if a.isdigit() and b.isdigit():
                lo, hi = int(a), int(b)
                if lo > hi:
                    lo, hi = hi, lo
                for k in range(lo, hi + 1):
                    if 1 <= k <= n:
                        out.add(k - 1)
            continue
        if part.isdigit():
            k = int(part)
            if 1 <= k <= n:
                out.add(k - 1)
            continue

    return sorted(out)


def _discover_git_checkouts_under(root: Path) -> List[Path]:
    """Return top-level git checkouts under a root (ignores nested submodules).

    We consider any directory that contains a '.git' entry (file or dir) as a checkout.
    We then drop any candidates that live inside another candidate (submodules).
    """
    root = Path(root).expanduser().resolve()
    if not root.exists():
        return []

    candidates: set[Path] = set()
    for git_entry in root.rglob('.git'):
        try:
            parent = git_entry.parent
        except Exception:
            continue
        if parent == root:
            continue
        candidates.add(parent)

    # Keep only the outermost candidates.
    ordered = sorted(candidates, key=lambda p: len(p.parts))
    kept: list[Path] = []
    for c in ordered:
        if any(parent in kept for parent in c.parents):
            continue
        kept.append(c)

    return sorted(kept, key=lambda p: p.as_posix())


def _case_id_from_pathlike(rel: str) -> str:
    """Derive a stable case_id from a relative path / branch name.

    We use '__' for path separators to avoid collisions between:
      - 'a/b'  -> 'a__b'
      - 'a_b'  -> 'a_b'
    """
    rel = (rel or '').strip().replace('\\\\', '/').strip('/')
    return safe_name(rel.replace('/', '__') or 'case')


def _suite_case_from_repo_path(
    *,
    case_id: str,
    repo_path: Path,
    label: Optional[str] = None,
    branch: Optional[str] = None,
    track: Optional[str] = None,
    tags: Optional[dict] = None,
    overrides: Optional[SuiteCaseOverrides] = None,
) -> SuiteCase:
    """Create a SuiteCase for a local repo path."""
    cid = safe_name(case_id)
    repo_path = Path(repo_path).expanduser().resolve()
    lbl = label or cid
    rn = safe_name(cid)
    repo = RepoSpec(repo_key=None, repo_url=None, repo_path=str(repo_path))
    c = CaseSpec(
        case_id=cid,
        runs_repo_name=rn,
        label=lbl,
        repo=repo,
        branch=branch,
        track=track,
        tags=tags or {},
    )
    return SuiteCase(case=c, overrides=overrides or SuiteCaseOverrides())


def _load_suite_cases_from_csv(csv_path: Path) -> List[SuiteCase]:
    """Load SuiteCase entries from a CSV file.

    Supported formats
    -----------------
    1) With header (recommended):
         case_id,repo_path,label,branch,track,tags_json,sonar_project_key,aikido_git_ref

    2) Without header (positional):
         repo_path
         case_id,repo_path
         case_id,repo_path,label,branch,track,tags_json

    Notes
    -----
    - Blank lines and lines starting with '#' are ignored.
    - tags_json should be a JSON object like: {"set":"core"}
    """
    p = Path(csv_path).expanduser().resolve()
    if not p.exists():
        raise SystemExit(f"Cases CSV not found: {p}")

    rows: list[list[str]] = []
    with p.open('r', encoding='utf-8', newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            if row and row[0].strip().startswith('#'):
                continue
            cleaned = [c.strip() for c in row]
            if all(not c for c in cleaned):
                continue
            rows.append(cleaned)

    if not rows:
        return []

    header = [c.lower() for c in rows[0]]
    has_header = 'repo_path' in header or 'repo_url' in header or 'repo_key' in header

    out: list[SuiteCase] = []

    def parse_tags(raw: str) -> dict:
        if not raw:
            return {}
        try:
            v = json.loads(raw)
            return v if isinstance(v, dict) else {}
        except Exception:
            return {}

    if has_header:
        keys = header
        for r in rows[1:]:
            d = {keys[i]: (r[i] if i < len(r) else '') for i in range(len(keys))}

            case_id = d.get('case_id') or ''
            repo_path = d.get('repo_path') or ''
            repo_url = d.get('repo_url') or ''
            repo_key = d.get('repo_key') or ''

            label = d.get('label') or None
            branch = d.get('branch') or None
            commit = d.get('commit') or None
            track = d.get('track') or None
            tags = parse_tags(d.get('tags') or d.get('tags_json') or '')

            overrides = SuiteCaseOverrides(
                sonar_project_key=(d.get('sonar_project_key') or None),
                aikido_git_ref=(d.get('aikido_git_ref') or None),
            )

            if repo_path:
                rp = Path(repo_path).expanduser().resolve()
                if not case_id:
                    case_id = rp.name
                sc = _suite_case_from_repo_path(
                    case_id=case_id,
                    repo_path=rp,
                    label=label,
                    branch=branch,
                    track=track,
                    tags=tags,
                    overrides=overrides,
                )
                # Patch in commit if present
                if commit:
                    c = sc.case
                    sc = SuiteCase(case=CaseSpec(**{**c.__dict__, 'commit': commit}), overrides=sc.overrides)
                out.append(sc)
                continue

            # URL/key-based case (rare in micro-suites; supported for completeness)
            if repo_url or repo_key:
                if not case_id:
                    case_id = repo_key or repo_id_from_repo_url(repo_url)
                cid = safe_name(case_id)
                lbl = label or cid
                runs_repo_name = safe_name(d.get('runs_repo_name') or cid)
                repo = RepoSpec(repo_key=repo_key or None, repo_url=repo_url or None, repo_path=None)
                case = CaseSpec(
                    case_id=cid,
                    runs_repo_name=runs_repo_name,
                    label=lbl,
                    repo=repo,
                    branch=branch,
                    commit=commit,
                    track=track,
                    tags=tags,
                )
                out.append(SuiteCase(case=case, overrides=overrides))
                continue

        return out

    # Positional mode (no header)
    for r in rows:
        if len(r) == 1:
            repo_path = r[0]
            rp = Path(repo_path).expanduser().resolve()
            out.append(_suite_case_from_repo_path(case_id=rp.name, repo_path=rp, label=rp.name, branch=None))
            continue

        case_id = r[0]
        repo_path = r[1] if len(r) > 1 else ''
        label = r[2] if len(r) > 2 else None
        branch = r[3] if len(r) > 3 else None
        track = r[4] if len(r) > 4 else None
        tags = parse_tags(r[5] if len(r) > 5 else '')

        rp = Path(repo_path).expanduser().resolve()
        out.append(_suite_case_from_repo_path(
            case_id=case_id,
            repo_path=rp,
            label=label,
            branch=branch,
            track=track,
            tags=tags,
        ))

    return out


def _load_suite_cases_from_worktrees_root(worktrees_root: Path) -> List[SuiteCase]:
    root = Path(worktrees_root).expanduser().resolve()
    repos = _discover_git_checkouts_under(root)

    out: list[SuiteCase] = []
    for repo_dir in repos:
        try:
            rel = repo_dir.relative_to(root).as_posix()
        except Exception:
            rel = repo_dir.name
        case_id = _case_id_from_pathlike(rel)
        out.append(_suite_case_from_repo_path(
            case_id=case_id,
            repo_path=repo_dir,
            label=rel,
            branch=rel,
        ))

    return out


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
    print("   - Suite definition files are optional; suite.json/case.json/run.json are always written.\n")

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
                "add_worktrees": "Add cases from local worktrees",
                "add_csv": "Add cases from CSV file",
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
            csv_in = _prompt_text("Cases CSV path", default="suites/cases.csv").strip()
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



def _write_suite_py(path: str | Path, suite_def: SuiteDefinition) -> Path:
    """Write a suite definition as a Python file exporting SUITE_DEF.

    This is intended for *reruns* and provenance. Runtime orchestration must not use YAML/JSON.
    """
    p = Path(path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)

    raw = suite_def.to_dict()
    # Keep this file minimal and stable.
    content = (
        "from pipeline.suite_definition import SuiteDefinition\n\n"
        f"SUITE_RAW = {json.dumps(raw, indent=2, sort_keys=True)}\n\n"
        "SUITE_DEF = SuiteDefinition.from_dict(SUITE_RAW)\n"
    )
    p.write_text(content, encoding="utf-8")
    return p


def _resolve_suite_case_for_run(sc: SuiteCase) -> Tuple[SuiteCase, str]:
    """Legacy shim.

    Suite-mode resolution now happens through the explicit resolver boundary
    (:func:`pipeline.suite_resolver.resolve_suite_run`). This helper remains as
    a thin adapter for older codepaths/experiments.
    """
    from pipeline.suite_resolver import resolve_suite_case

    return resolve_suite_case(sc, repo_registry=REPOS)




def _build_suite_from_sources(args: argparse.Namespace) -> SuiteDefinition:
    """Build a suite definition without interactive prompts.

    Sources:
      - --cases-from CSV
      - --worktrees-root folder

    This is meant for prototype automation and CI.
    """
    suite_id = str(args.bundle_id) if args.bundle_id else new_suite_id()

    scanners_csv = args.scanners or "semgrep,snyk,sonar,aikido"
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


def run_suite_mode(args: argparse.Namespace, pipeline: SASTBenchmarkPipeline) -> int:
    """Run multiple cases under one suite id.

    Suite definitions are Python-only at runtime:
    - If --suite-file is provided, it must be a .py file exporting SUITE_DEF.
    - Otherwise we prompt interactively.
    """

    if args.no_bundle:
        print("❌ Suite mode requires suite layout (do not use --no-suite).")
        return 2

    # Keep suite_root anchored under the repo root unless the user passed an
    # absolute path. This prevents "worked on my laptop" path drift when the
    # CLI is invoked from different working directories.
    suite_root = anchor_under_repo_root(Path(args.bundle_root).expanduser())

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
            suite_def = _build_suite_interactively(args)

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

    # -----------------------------------------------------------------
    # Resolver boundary (NEW)
    # -----------------------------------------------------------------
    # Turn whatever "suite input" we used (suite file / CSV / worktrees / interactive)
    # into a canonical suite run manifest under runs/suites/<suite_id>/suite.json.
    #
    # After this call, downstream execution should rely on the resolved
    # cases + suite.json, not on re-deriving IDs from inputs.
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
        repo_registry=REPOS,
        ensure_dirs=True,
    )

    # Use the canonical, sanitized identifiers from the resolver.
    suite_id = resolved_run.suite_id
    suite_dir = resolved_run.suite_dir

    # If suite was built interactively, optionally write a Python suite file for reruns.
    if not args.suite_file:
        if _prompt_yes_no("Save this suite definition to a Python file for reruns?", default=False):
            default_out = suite_dir / "suite_definition.py"
            out_path = _prompt_text("Python output path", default=str(default_out)).strip() or str(default_out)

            to_write = SuiteDefinition(
                suite_id=suite_id,
                scanners=scanners,
                cases=[rc.suite_case for rc in resolved_run.cases],
                analysis=analysis_defaults,
            )
            try:
                _write_suite_py(out_path, to_write)
                print(f"  ✅ Wrote suite definition: {out_path}")
            except Exception as e:
                print(f"  ⚠️  Failed to write suite definition .py: {e}")

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
            skip_analysis=bool(skip_analysis),
            tolerance=int(tolerance),
            analysis_filter=str(analysis_filter),
            sonar_project_key=sc.overrides.sonar_project_key or args.sonar_project_key,
            aikido_git_ref=sc.overrides.aikido_git_ref or args.aikido_git_ref,
            argv=list(sys.argv),
            python_executable=sys.executable,
        )

        rc = int(pipeline.run(req))
        overall = max(overall, rc)

    print("\n✅ Suite complete")
    print(f"  Suite id : {suite_id}")
    print(f"  Suite dir: {suite_dir}")
    return overall


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    # Build the pipeline facade (also loads .env by default).
    pipeline = build_pipeline(load_dotenv=True)

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
        raise SystemExit(run_suite_mode(args, pipeline))

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
        raise SystemExit(pipeline.analyze(req))

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
        raise SystemExit(pipeline.run(req))

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

    raise SystemExit(pipeline.run(req))


if __name__ == "__main__":
    main()
