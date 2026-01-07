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
3) analyze
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
# Benchmark Juice Shop into a new bundle (then run analysis suite)
python sast_cli.py --mode benchmark --repo-key juice_shop --scanners semgrep,snyk,sonar

# Same, but pick a specific bundle id
python sast_cli.py --mode benchmark --repo-key juice_shop --bundle-id 20260104T013000Z

# Analyze the latest bundle for a target
python sast_cli.py --mode analyze --metric suite --repo-key juice_shop --bundle-id latest

# Legacy behavior (write directly to runs/<tool>/...)
python sast_cli.py --mode benchmark --repo-key juice_shop --no-bundle
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pipeline.layout import (
    SuitePaths,
    ensure_suite_dirs,
    get_suite_paths,
    new_suite_id,
    resolve_case_dir,
    update_suite_artifacts,
    write_latest_suite_pointer,
    discover_repo_dir,
    discover_latest_run_dir,
)

# Centralized command builder (prevents per-CLI drift)
from pipeline.core import (
    ROOT_DIR as PIPELINE_ROOT_DIR,
    SUPPORTED_SCANNERS,
    build_scan_command,
    derive_sonar_project_key,
    repo_id_from_repo_url,
    sanitize_sonar_key_fragment,
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


def require_env(var: str) -> None:
    if not os.getenv(var):
        raise SystemExit(f"Missing {var}. Put it in {ENV_PATH} (or export it in your shell).")


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
        choices=["scan", "benchmark", "analyze"],
        help="scan = one tool, benchmark = multiple tools, analyze = compute metrics from existing runs",
    )
    parser.add_argument(
        "--scanner",
        choices=sorted(SUPPORTED_SCANNERS),
        help="(scan mode) Which scanner to run",
    )
    parser.add_argument(
        "--scanners",
        help="(benchmark mode) Comma-separated scanners (default: semgrep,snyk,sonar,aikido)",
    )

    # Bundle layout
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
        help="(benchmark mode) Skip the analysis suite step (scans only).",
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
            "If using bundles, default is <bundle>/analysis/."
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
# Execution helpers
# -------------------------------------------------------------------

def run_one(cmd: List[str], dry_run: bool, quiet: bool = False) -> int:
    print("  Command :", " ".join(cmd))
    if dry_run:
        print("  (dry-run: not executing)")
        return 0

    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")

    if quiet:
        result = subprocess.run(
            cmd,
            env=env,
            cwd=str(ROOT_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        result = subprocess.run(cmd, env=env, cwd=str(ROOT_DIR))

    return result.returncode


def _load_json_if_exists(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists() or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sonar_extra_args(args: argparse.Namespace, repo_id: str) -> Dict[str, str]:
    require_env("SONAR_ORG")
    require_env("SONAR_TOKEN")

    if args.sonar_project_key:
        project_key = args.sonar_project_key
    else:
        project_key = derive_sonar_project_key(os.environ["SONAR_ORG"], repo_id)

    return {"project-key": project_key}


def _merge_dicts(a: Optional[Dict[str, Any]], b: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if a:
        out.update(a)
    if b:
        out.update(b)
    return out



def _detect_git_branch(repo_path: Optional[str]) -> Optional[str]:
    """Best-effort detect current git branch name for a local repo checkout.

    Returns None if repo_path is missing, not a git repo, or in detached HEAD.
    """
    if not repo_path:
        return None
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_path), "rev-parse", "--abbrev-ref", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if not out or out == "HEAD":
            return None
        return out
    except Exception:
        return None


def _write_manifest(path: Path, manifest: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _write_run_json(
    run_dir: Path,
    *,
    suite_id: str,
    case_id: str,
    tool: str,
    repo_name: str,
    exit_code: int,
    command: str,
    started: Optional[str] = None,
    finished: Optional[str] = None,
) -> None:
    """Write run_dir/run.json (DB-ingestion friendly pointer file).

    This file is intentionally small: it records identifiers and the artifact filenames
    that live next to it (normalized/raw/metadata/logs).

    It does **not** duplicate the full normalized findings payload.
    """
    run_id = run_dir.name

    def _pick_first(candidates: list[str]) -> Optional[str]:
        for name in candidates:
            p = run_dir / name
            if p.exists() and p.is_file():
                return name
        return None

    normalized_name = _pick_first(["normalized.json", f"{repo_name}.normalized.json"])
    raw_name = _pick_first(["raw.sarif", "raw.json", f"{repo_name}.sarif", f"{repo_name}.json"])
    metadata_name = _pick_first(["metadata.json"])
    logs_dir = run_dir / "logs"
    logs_dir_name = "logs" if logs_dir.exists() and logs_dir.is_dir() else None

    data: Dict[str, Any] = {
        "suite_id": suite_id,
        "case_id": case_id,
        "tool": tool,
        "run_id": run_id,
        "started": started,
        "finished": finished,
        "exit_code": int(exit_code),
        "command": command,
        "artifacts": {
            "normalized": normalized_name,
            "raw": raw_name,
            "metadata": metadata_name,
            "logs_dir": logs_dir_name,
        },
    }

    (run_dir / "run.json").write_text(json.dumps(data, indent=2), encoding="utf-8")


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main() -> None:
    load_dotenv_if_present(ENV_PATH)
    args = parse_args()

    # mode selection
    mode = args.mode
    if mode is None:
        if args.scanner or args.repo_key or args.repo_url or args.repo_path:
            mode = "scan"
        else:
            mode = choose_from_menu(
                "Choose an action:",
                {
                    "scan": "Scan a repo with a single tool",
                    "benchmark": "Run multiple scanners on a repo",
                    "analyze": "Analyze existing normalized runs (metrics)",
                },
            )

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

    # ------------------- ANALYZE MODE ------------------
    if mode == "analyze":
        metric = args.metric or "hotspots"

        tools_csv = args.tools or "snyk,semgrep,sonar,aikido"
        tools = [t for t in _parse_csv(tools_csv) if t in SUPPORTED_SCANNERS]
        if not tools:
            raise SystemExit("No valid tools specified for analyze mode.")

        # If analyzing a bundle, runs_dir is bundle/scans and out_dir is bundle/analysis.
        bundle_dir: Optional[Path] = None
        if args.bundle_path:
            bundle_dir = Path(args.bundle_path).resolve()
        elif args.bundle_id:
            bundle_dir = resolve_case_dir(
                case_id=case_id,
                suite_id=str(args.bundle_id),
                suite_root=args.bundle_root,
            )

        if bundle_dir is not None:
            # v2 layout: tool_runs/ (preferred). v1: scans/ (legacy fallback).
            runs_dir = bundle_dir / "tool_runs"
            if not runs_dir.exists():
                legacy = bundle_dir / "scans"
                if legacy.exists():
                    runs_dir = legacy
            default_out_dir = bundle_dir / "analysis"
        else:
            runs_dir = Path(args.runs_dir).resolve()
            default_out_dir = runs_dir / "analysis" / runs_repo_name

        if metric == "suite":
            out_dir = Path(args.analysis_out_dir).resolve() if args.analysis_out_dir else default_out_dir
            out_dir.mkdir(parents=True, exist_ok=True)

            from pipeline.analysis.analyze_suite import run_suite

            summary = run_suite(
                repo_name=runs_repo_name,
                tools=tools,
                runs_dir=runs_dir,
                out_dir=out_dir,
                tolerance=int(args.tolerance),
                mode=str(args.analysis_filter),
                formats=["json", "csv"],
            )

            print("\n✅ Analysis suite complete")
            print(f"  Repo (runs dir): {runs_repo_name}")
            print(f"  Tools         : {', '.join(tools)}")
            print(f"  Runs dir      : {runs_dir}")
            print(f"  Output dir    : {out_dir}")
            print(f"  Benchmark pack: {out_dir / 'benchmark_pack.json'}")

            if args.format == "json":
                print(json.dumps(summary, indent=2))
            else:
                print(json.dumps(summary, indent=2))
            raise SystemExit(0)

        # metric == hotspots
        out_path = Path(args.out) if args.out else (default_out_dir / "latest_hotspots_by_file.json")
        out_path.parent.mkdir(parents=True, exist_ok=True)

        from pipeline.analysis.unique_overview import analyze_latest_hotspots_for_repo, print_text_report

        try:
            report = analyze_latest_hotspots_for_repo(
                runs_repo_name,
                tools=tools,
                runs_dir=runs_dir,
            )
        except FileNotFoundError as e:
            print("\n⚠️  No normalized runs found for analysis.")
            print("   Expected layout:")
            print("     v2: <runs_dir>/<tool>/<run_id>/normalized.json")
            print("     v1: <runs_dir>/<tool>/<repo_name>/<run_id>/<repo_name>.normalized.json")
            print(f"   runs_dir       : {runs_dir}")
            print(f"   repo_name      : {runs_repo_name}")
            print(f"   tools          : {', '.join(tools)}")
            print(f"\n   Details: {e}")
            raise SystemExit(1)

        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        print("\n📊 Hotspots-by-file report")
        print(f"  Repo (runs dir): {runs_repo_name}")
        print(f"  Tools         : {', '.join(tools)}")
        print(f"  Runs dir      : {runs_dir}")
        print(f"  Saved report  : {out_path}")

        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print_text_report(report, max_unique=args.max_unique)

        raise SystemExit(0)

    # --------------------- SCAN MODE ---------------------
    if mode == "scan":
        scanner = args.scanner
        if scanner is None:
            scanner = choose_from_menu(
                "Choose a scanner:",
                {k: SCANNER_LABELS.get(k, k) for k in sorted(SUPPORTED_SCANNERS)},
            )

        # Bundle handling
        bundle: Optional[SuitePaths] = None
        if not args.no_bundle:
            sid = str(args.bundle_id) if args.bundle_id else new_suite_id()
            bundle = get_suite_paths(case_id=case_id, suite_id=sid, suite_root=args.bundle_root)
            ensure_suite_dirs(bundle)
            write_latest_suite_pointer(bundle)

        extra_args: Dict[str, Any] = {}
        if scanner == "sonar":
            extra_args = sonar_extra_args(args, repo_id)
            print(f"  Sonar project key : {extra_args.get('project-key')}")

        # When bundling, force output-root under the bundle.

        # Aikido cloud multi-branch scanning: pass current git branch so we select
        # the correct branch-clone repo inside Aikido when multi-branch scanning is enabled.
        if scanner == "aikido":
            b = _detect_git_branch(repo_path)
            if b:
                extra_args = _merge_dicts(extra_args, {"branch": b})

        if scanner == "aikido" and args.aikido_git_ref:
            extra_args = _merge_dicts(extra_args, {"git-ref": args.aikido_git_ref})
        if bundle is not None:
            extra_args = _merge_dicts(extra_args, {"output-root": str(bundle.tool_runs_dir / scanner)})
            if scanner == "aikido":
                # Ensure Aikido writes to the same repo folder name for analysis.
                extra_args = _merge_dicts(extra_args, {"repo-name": runs_repo_name})

        cmd = build_scan_command(
            scanner,
            repo_url=repo_url,
            repo_path=repo_path,
            extra_args=extra_args,
            python_executable=sys.executable or "python",
        )

        print("\n🚀 Running scan")
        print(f"  Scanner : {scanner}")
        print(f"  Target  : {label}")

        started = _now_iso()
        code = run_one(cmd, args.dry_run, args.quiet)
        finished = _now_iso()

        # Manifest (only when bundling)
        if bundle is not None:
            tool_out_root = bundle.tool_runs_dir / scanner
            repo_dir = discover_repo_dir(tool_out_root, prefer=runs_repo_name)
            run_dir = discover_latest_run_dir(repo_dir) if repo_dir else None
            metadata = _load_json_if_exists((run_dir / "metadata.json") if run_dir else Path("/nonexistent"))

            # Write per-tool run.json (DB-ingestion friendly pointer file)
            if run_dir:
                try:
                    _write_run_json(
                        run_dir,
                        suite_id=bundle.bundle_id,
                        case_id=bundle.target,
                        tool=scanner,
                        repo_name=runs_repo_name,
                        exit_code=code,
                        command=" ".join(cmd),
                        started=started,
                        finished=finished,
                    )
                except Exception:
                    pass

            run_json_path = str(run_dir / "run.json") if run_dir else None

            manifest: Dict[str, Any] = {
                "suite": {"id": bundle.bundle_id, "suite_dir": str(bundle.suite_dir)},
                "case": {"id": bundle.target, "case_dir": str(bundle.case_dir)},
                "repo": {
                    "label": label,
                    "repo_url": repo_url,
                    "repo_path": repo_path,
                    "runs_repo_name": runs_repo_name,
                },
                "invocation": {
                    "mode": "scan",
                    "argv": sys.argv,
                    "python": sys.executable,
                },
                "timestamps": {"started": started, "finished": finished},
                "scanners_requested": [scanner],
                "tool_runs": {
                    scanner: {
                        "exit_code": code,
                        "command": " ".join(cmd),
                        "output_root": str(tool_out_root),
                        "repo_dir": str(repo_dir) if repo_dir else None,
                        "run_id": run_dir.name if run_dir else None,
                        "run_dir": str(run_dir) if run_dir else None,
                        "run_json": run_json_path,
                        "metadata": metadata,
                    }
                },
            }
            _write_manifest(bundle.case_json_path, manifest)
            update_suite_artifacts(bundle, manifest)
            print(f"\n📦 Case dir: {bundle.case_dir}")
            print(f"   Manifest: {bundle.case_json_path}")

        if code == 0:
            print("\n✅ Scan completed.")
        else:
            print(f"\n⚠️ Scan finished with exit code {code}")
        raise SystemExit(code)

    # ------------------- BENCHMARK MODE ------------------
    scanners_arg = args.scanners or "semgrep,snyk,sonar,aikido"
    scanners = [s for s in _parse_csv(scanners_arg) if s in SUPPORTED_SCANNERS]
    if not scanners:
        raise SystemExit("No valid scanners specified for benchmark mode.")

    # Bundle handling (default)
    bundle: Optional[SuitePaths] = None
    if not args.no_bundle:
        sid = str(args.bundle_id) if args.bundle_id else new_suite_id()
        bundle = get_suite_paths(case_id=case_id, suite_id=sid, suite_root=args.bundle_root)
        ensure_suite_dirs(bundle)
        write_latest_suite_pointer(bundle)

    print("\n🚀 Running benchmark (multi-scanner loop)")
    print(f"  Target   : {label}")
    print(f"  Repo name: {runs_repo_name}")
    print(f"  Scanners : {', '.join(scanners)}")
    if bundle is not None:
        print(f"  Suite id : {bundle.bundle_id}")
        print(f"  Suite dir: {bundle.suite_dir}")
        print(f"  Case dir : {bundle.case_dir}")

    started = _now_iso()
    tool_runs_manifest: Dict[str, Any] = {}

    overall = 0
    for scanner in scanners:
        print("\n----------------------------------------")
        print(f"▶ {scanner}")

        extra_args: Dict[str, Any] = {}
        if scanner == "sonar":
            extra_args = sonar_extra_args(args, repo_id)
            print(f"  Sonar project key : {extra_args.get('project-key')}")


        # Aikido cloud multi-branch scanning: pass current git branch so we select
        # the correct branch-clone repo inside Aikido when multi-branch scanning is enabled.
        if scanner == "aikido":
            b = _detect_git_branch(repo_path)
            if b:
                extra_args = _merge_dicts(extra_args, {"branch": b})

        if scanner == "aikido" and args.aikido_git_ref:
            extra_args = _merge_dicts(extra_args, {"git-ref": args.aikido_git_ref})
        if bundle is not None:
            extra_args = _merge_dicts(extra_args, {"output-root": str(bundle.tool_runs_dir / scanner)})
            if scanner == "aikido":
                extra_args = _merge_dicts(extra_args, {"repo-name": runs_repo_name})

        cmd = build_scan_command(
            scanner,
            repo_url=repo_url,
            repo_path=repo_path,
            extra_args=extra_args,
            python_executable=sys.executable or "python",
        )

        tool_started = _now_iso()
        code = run_one(cmd, args.dry_run, args.quiet)
        tool_finished = _now_iso()
        if code != 0:
            overall = code

        # Record run info (best-effort)
        if bundle is not None:
            tool_out_root = bundle.tool_runs_dir / scanner
            repo_dir = discover_repo_dir(tool_out_root, prefer=runs_repo_name)
            run_dir = discover_latest_run_dir(repo_dir) if repo_dir else None
            metadata = _load_json_if_exists((run_dir / "metadata.json") if run_dir else Path("/nonexistent"))

            # Write per-tool run.json (DB-ingestion friendly pointer file)
            if run_dir:
                try:
                    _write_run_json(
                        run_dir,
                        suite_id=bundle.bundle_id,
                        case_id=bundle.target,
                        tool=scanner,
                        repo_name=runs_repo_name,
                        exit_code=code,
                        command=" ".join(cmd),
                        started=tool_started,
                        finished=tool_finished,
                    )
                except Exception:
                    pass

            run_json_path = str(run_dir / "run.json") if run_dir else None

            tool_runs_manifest[scanner] = {
                "exit_code": code,
                "command": " ".join(cmd),
                "started": tool_started,
                "finished": tool_finished,
                "output_root": str(tool_out_root),
                "repo_dir": str(repo_dir) if repo_dir else None,
                "run_id": run_dir.name if run_dir else None,
                "run_dir": str(run_dir) if run_dir else None,
                "run_json": run_json_path,
                "metadata": metadata,
            }

    analysis_summary: Optional[Dict[str, Any]] = None

    # Auto-analysis (only makes sense when bundling)
    if bundle is not None and not args.skip_analysis:
        print("\n----------------------------------------")
        print("▶ analysis suite")

        # Only include tools that actually produced a normalized JSON in this bundle.
        from pipeline.analysis.run_discovery import find_latest_normalized_json

        available_tools: List[str] = []
        for tool in scanners:
            try:
                find_latest_normalized_json(runs_dir=bundle.tool_runs_dir, tool=tool, repo_name=runs_repo_name)
                available_tools.append(tool)
            except FileNotFoundError:
                print(f"  ⚠️  missing normalized JSON for {tool}; skipping it in analysis")

        if available_tools:
            from pipeline.analysis.analyze_suite import run_suite

            analysis_summary = run_suite(
                repo_name=runs_repo_name,
                tools=available_tools,
                runs_dir=bundle.tool_runs_dir,
                out_dir=bundle.analysis_dir,
                tolerance=int(args.tolerance),
                mode=str(args.analysis_filter),
                formats=["json", "csv"],
            )
            print(f"  ✅ analysis complete: {bundle.analysis_dir}")
        else:
            print("  ⚠️  no tool outputs found; skipping analysis")

    finished = _now_iso()

    if bundle is not None:
        manifest: Dict[str, Any] = {
            "suite": {"id": bundle.bundle_id, "suite_dir": str(bundle.suite_dir)},
            "case": {"id": bundle.target, "case_dir": str(bundle.case_dir)},
            "repo": {
                "label": label,
                "repo_url": repo_url,
                "repo_path": repo_path,
                "runs_repo_name": runs_repo_name,
            },
            "invocation": {
                "mode": "benchmark",
                "argv": sys.argv,
                "python": sys.executable,
                "skip_analysis": bool(args.skip_analysis),
            },
            "timestamps": {"started": started, "finished": finished},
            "scanners_requested": scanners,
            "tool_runs": tool_runs_manifest,
            "analysis": analysis_summary,
        }
        _write_manifest(bundle.case_json_path, manifest)
        update_suite_artifacts(bundle, manifest)

        print("\n📦 Case complete")
        print(f"  Suite id : {bundle.bundle_id}")
        print(f"  Suite dir: {bundle.suite_dir}")
        print(f"  Case dir : {bundle.case_dir}")
        print(f"  Tool runs: {bundle.tool_runs_dir}")
        print(f"  Analysis : {bundle.analysis_dir if not args.skip_analysis else '(skipped)'}")
        print(f"  Manifest : {bundle.case_json_path}")
        print(f"  Summary  : {bundle.suite_summary_path}")

    if overall == 0:
        print("\n✅ Benchmark completed (all scanners exited 0).")
    else:
        print(f"\n⚠️ Benchmark completed with non-zero exit code: {overall}")

    raise SystemExit(overall)


if __name__ == "__main__":
    main()
