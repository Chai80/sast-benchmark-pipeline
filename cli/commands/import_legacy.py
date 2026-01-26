from __future__ import annotations

"""cli.commands.import_legacy

Import (migrate) legacy runs/<tool>/... outputs into the canonical suite layout.

This is intentionally a *filesystem orchestration* command:
- no tool execution
- no analysis
- no prompts

Once imported, you can run the normal analysis pipeline:
  python sast_cli.py --mode analyze --metric suite --suite-id <suite_id>
"""

import sys

from pathlib import Path
from typing import Dict, Optional

from cli.common import derive_runs_repo_name, parse_csv
from pipeline.pipeline import SASTBenchmarkPipeline
from pipeline.scanners import DEFAULT_SCANNERS_CSV, SUPPORTED_SCANNERS
from pipeline.suites.legacy_import import import_legacy_repo_to_suite


def _parse_tools(args) -> list[str]:
    # Prefer --tools (analyze-style), fallback to --scanners (benchmark-style).
    raw = (
        getattr(args, "tools", None)
        or getattr(args, "scanners", None)
        or DEFAULT_SCANNERS_CSV
    )
    tools = [t for t in parse_csv(str(raw)) if t in SUPPORTED_SCANNERS]
    if not tools:
        raise SystemExit("No valid tools specified. Pass --tools semgrep,snyk,...")
    return tools


def run_import_legacy(
    args,
    _pipeline: SASTBenchmarkPipeline,
    *,
    repo_registry: Dict[str, Dict[str, str]],
) -> int:
    """Entry point for `--mode import`.

    Returns exit code.
    """

    suite_root = Path(args.suite_root).expanduser().resolve()
    suite_id: Optional[str] = str(args.suite_id) if args.suite_id else None

    runs_dir = Path(args.runs_dir).expanduser().resolve()

    # Optional repo context (for nicer manifests). Import should not prompt.
    repo_url: Optional[str] = None
    repo_path: Optional[str] = None
    repo_label: Optional[str] = None

    if getattr(args, "repo_key", None):
        entry = repo_registry.get(str(args.repo_key)) or {}
        repo_url = entry.get("repo_url")
        repo_label = entry.get("label") or str(args.repo_key)
    elif getattr(args, "repo_url", None):
        repo_url = str(args.repo_url)
        repo_label = str(args.repo_url)
    elif getattr(args, "repo_path", None):
        repo_path = str(Path(str(args.repo_path)).expanduser().resolve())
        repo_label = Path(repo_path).name

    # Legacy runs use a repo-name folder under runs/<tool>/.
    runs_repo_name = getattr(args, "runs_repo_name", None) or derive_runs_repo_name(
        repo_url=repo_url,
        repo_path=repo_path,
        fallback=str(repo_label or "repo"),
    )
    if not runs_repo_name:
        raise SystemExit(
            "Unable to determine runs_repo_name. Pass --runs-repo-name <repo_folder>."
        )

    case_id = getattr(args, "case_id", None) or runs_repo_name

    tools = _parse_tools(args)
    import_run_id = str(getattr(args, "import_run_id", "latest") or "latest").strip()
    link_mode = str(getattr(args, "import_link_mode", "copy") or "copy").strip()

    res = import_legacy_repo_to_suite(
        suite_root=suite_root,
        suite_id=suite_id,
        case_id=str(case_id),
        runs_dir=runs_dir,
        runs_repo_name=str(runs_repo_name),
        tools=tools,
        import_run_id=import_run_id,
        link_mode=link_mode,
        repo_label=str(repo_label or runs_repo_name),
        repo_url=repo_url,
        repo_path=repo_path,
        track=str(args.track).strip() if getattr(args, "track", None) else None,
        argv=list(sys.argv),
        python_executable=sys.executable,
    )

    print("\n📦 Legacy import complete")
    print(f"  Suite id : {res.suite_id}")
    print(f"  Suite dir: {res.suite_dir}")
    print(f"  Case id  : {res.case_id}")
    print(f"  Case dir : {res.case_dir}")
    print(
        f"  Tools    : {', '.join(res.imported_tools) if res.imported_tools else '(none)'}"
    )

    if res.missing_tools:
        print(f"  ⚠️  Missing tools (no runs found): {', '.join(res.missing_tools)}")

    print("\nNext:")
    print(
        f"  python sast_cli.py --mode analyze --metric suite --suite-id {res.suite_id}"
    )

    # Non-zero only if nothing imported.
    return 0 if res.imported_tools else 2
