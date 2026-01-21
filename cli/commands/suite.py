from __future__ import annotations

import argparse
import fnmatch
import pprint
import re
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cli.common import derive_runs_repo_name, parse_csv
from cli.ui import choose_from_menu, _parse_index_selection, _prompt_text, _prompt_yes_no
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
from pipeline.suites.bundles import anchor_under_repo_root, safe_name
from pipeline.core import ROOT_DIR as PIPELINE_ROOT_DIR, repo_id_from_repo_url
from pipeline.suites.layout import new_suite_id
from pipeline.models import CaseSpec
from pipeline.orchestrator import AnalyzeRequest, RunRequest
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

def _default_owasp_micro_suite_worktrees_root() -> Optional[Path]:
    """Default micro-suite worktrees root (if present on disk).

    Keeps the QA calibration runbook deterministic for our current OWASP micro-suites.
    If the default path doesn't exist, callers should fall back to explicit --worktrees-root/--cases-from.
    """
    p = ROOT_DIR / "repos" / "worktrees" / "durinn-owasp2021-python-micro-suite"
    return p if p.is_dir() else None


def _default_owasp_micro_suite_cases_csv() -> Optional[Path]:
    """Default deterministic case list for the micro-suite QA (if present)."""
    p = ROOT_DIR / "examples" / "suite_inputs" / "durinn-owasp2021-python-micro-suite_cases.csv"
    return p if p.is_file() else None



# ---------------------------------------------------------------------------
# QA helpers: triage calibration
#
# The triage calibration pipeline is suite-level, but per-case triage artifacts
# (triage_queue.csv) are emitted during per-case analysis. In a normal suite
# run, triage_queue.csv is therefore generated *before* the suite-level
# triage_calibration.json exists. The QA runbook for calibration does a
# two-pass workflow:
#   1) run the suite (scan + analysis) and build suite-level calibration assets
#   2) re-run analyze across all cases so per-case triage_queue.csv can include
#      triage_score_v1.
# ---------------------------------------------------------------------------

_OWASP_ID_RE = re.compile(r"\bA(0[1-9]|10)\b", re.IGNORECASE)
_OWASP_RANGE_RE = re.compile(r"(?i)^A?(\d{1,2})\s*(?:-|\.\.)\s*A?(\d{1,2})$")
_OWASP_TOKEN_RE = re.compile(r"(?i)^A?(\d{1,2})$")


def _normalize_owasp_id(raw: str) -> str:
    """Normalize an OWASP category id to the form 'A01'..'A10'."""

    m = _OWASP_TOKEN_RE.match(raw.strip())
    if not m:
        raise ValueError(f"Invalid OWASP token: {raw!r}")
    n = int(m.group(1))
    if n < 1 or n > 10:
        raise ValueError(f"OWASP id out of range (1..10): {raw!r}")
    return f"A{n:02d}"


def _expand_owasp_spec_token(token: str) -> List[str]:
    """Expand a single token like 'A03' or 'A01-A10' into a list of IDs."""

    t = token.strip()
    if not t:
        return []

    # Normalize a few common range separators.
    t = t.replace("–", "-").replace("—", "-")

    m_range = _OWASP_RANGE_RE.match(t)
    if m_range:
        start = int(m_range.group(1))
        end = int(m_range.group(2))
        if start > end:
            start, end = end, start
        return [f"A{i:02d}" for i in range(start, end + 1) if 1 <= i <= 10]

    # Single token.
    return [_normalize_owasp_id(t)]


def _parse_qa_owasp_spec(raw: str) -> List[str]:
    """Parse --qa-owasp (CSV and simple ranges) into a deterministic list."""

    out: List[str] = []
    for tok in parse_csv(raw):
        for oid in _expand_owasp_spec_token(tok):
            if oid not in out:
                out.append(oid)
    return out


def _qa_target_owasp_ids(scope: str) -> List[str]:
    scope = (scope or "").strip().lower()
    if scope == "full":
        return [f"A{i:02d}" for i in range(1, 11)]
    # Default: smoke
    return ["A03", "A07"]


def _detect_owasp_id(*texts: object) -> Optional[str]:
    """Best-effort extraction of an OWASP token (A01..A10) from arbitrary inputs."""

    for t in texts:
        if t is None:
            continue
        m = _OWASP_ID_RE.search(str(t))
        if not m:
            continue
        return f"A{int(m.group(1)):02d}"
    return None


def _default_qa_cases_csv() -> Optional[Path]:
    """Default deterministic case list for QA (if present in the repo)."""

    p = ROOT_DIR / "examples" / "suite_inputs" / "durinn-owasp2021-python-micro-suite_cases.csv"
    return p if p.is_file() else None


def _default_qa_worktrees_root() -> Optional[Path]:
    """Default micro-suite worktrees root (if present on disk)."""

    p = ROOT_DIR / "repos" / "worktrees" / "durinn-owasp2021-python-micro-suite"
    return p if p.is_dir() else None


def _qa_matches_selector(haystack: str, selector: str) -> bool:
    """Case-insensitive match: substring by default, fnmatch if glob chars are present."""

    h = (haystack or "").lower()
    s = (selector or "").lower().strip()
    if not s:
        return False
    if any(ch in s for ch in ("*", "?", "[")):
        return fnmatch.fnmatch(h, s)
    return s in h


def _infer_case_owasp_id(suite_case: SuiteCase) -> Optional[str]:
    c = suite_case.case
    # Prefer explicit tokens in the user-visible identifiers.
    oid = _detect_owasp_id(c.case_id, c.branch, c.label)
    if oid:
        return oid
    # Fall back to tags (keys/values).
    for k, v in (c.tags or {}).items():
        oid = _detect_owasp_id(k, v)
        if oid:
            return oid
    return None


def _filter_suite_def_for_qa(suite_def: SuiteDefinition, args: argparse.Namespace) -> SuiteDefinition:
    """Return a SuiteDefinition filtered for QA selection."""

    # 1) Explicit case selectors override everything.
    qa_cases = getattr(args, "qa_cases", None)
    if qa_cases:
        selectors = [s.strip() for s in parse_csv(qa_cases) if s.strip()]

        def _match_case(sc: SuiteCase) -> bool:
            c = sc.case
            hay = [c.case_id, c.branch or "", c.label or ""]
            return any(_qa_matches_selector(str(h), sel) for h in hay for sel in selectors)

        selected = [sc for sc in suite_def.cases if _match_case(sc)]
        selected.sort(key=lambda sc: sc.case.case_id)
        if not selected:
            raise SystemExit(
                "qa-calibration: --qa-cases selection matched 0 cases. "
                "Selectors match case_id/branch/label (substring or glob)."
            )
        return SuiteDefinition(
            suite_id=suite_def.suite_id,
            scanners=suite_def.scanners,
            analysis=suite_def.analysis,
            cases=selected,
        )

    # 2) OWASP slice selection.
    qa_owasp = getattr(args, "qa_owasp", None)
    qa_scope = getattr(args, "qa_scope", None) or "smoke"
    wanted = set(_parse_qa_owasp_spec(qa_owasp) if qa_owasp else _qa_target_owasp_ids(qa_scope))
    selected: List[SuiteCase] = []
    for sc in suite_def.cases:
        oid = _infer_case_owasp_id(sc)
        if oid and oid in wanted:
            selected.append(sc)
    selected.sort(key=lambda sc: sc.case.case_id)
    if not selected:
        raise SystemExit(
            f"qa-calibration: OWASP selection matched 0 cases. wanted={sorted(wanted)} "
            "(matches A01..A10 tokens in case_id/branch/label/tags)."
        )
    return SuiteDefinition(
        suite_id=suite_def.suite_id,
        scanners=suite_def.scanners,
        analysis=suite_def.analysis,
        cases=selected,
    )


def _parse_scanners_str(value: str) -> List[str]:
    raw = parse_csv(value)
    scanners = [t for t in raw if t in SUPPORTED_SCANNERS]
    unknown = [t for t in raw if t not in SUPPORTED_SCANNERS]
    if unknown:
        print(f"  ⚠️  ignoring unknown scanners: {', '.join(unknown)}")
    return scanners


# --------------------------
# QA calibration helpers
# --------------------------

_OWASP_ID_RE = re.compile(r"\bA(0[1-9]|10)\b", flags=re.IGNORECASE)


def _detect_owasp_id(*texts: object) -> Optional[str]:
    """Detect an OWASP Top 10 id (A01..A10) from free-form text fields."""

    for t in texts:
        if not t:
            continue
        m = _OWASP_ID_RE.search(str(t))
        if m:
            return f"A{m.group(1)}"
    return None


def _normalize_owasp_id(token: str) -> str:
    """Normalize inputs like 'a3'/'A03' -> 'A03'."""

    s = str(token or "").strip().upper()
    m = re.match(r"^A?(\d{1,2})$", s)
    if not m:
        return s
    n = int(m.group(1))
    return f"A{n:02d}"


def _expand_owasp_token(token: str) -> List[str]:
    """Expand an OWASP selector token.

    Supports:
      - A03
      - A01-A10
      - A01..A10
    """

    raw = str(token or "").strip()
    if not raw:
        return []

    # Normalize unicode dashes that sometimes show up in pasted text.
    raw = raw.replace("–", "-").replace("—", "-")

    if raw.strip().lower() in {"all"}:
        return [f"A{i:02d}" for i in range(1, 11)]

    m = re.match(r"(?i)^A?(\d{1,2})\s*(?:\.\.|-)\s*A?(\d{1,2})$", raw)
    if m:
        a = int(m.group(1))
        b = int(m.group(2))
        lo, hi = (a, b) if a <= b else (b, a)
        lo = max(lo, 1)
        hi = min(hi, 10)
        return [f"A{i:02d}" for i in range(lo, hi + 1)]

    return [_normalize_owasp_id(raw)]


def _parse_qa_owasp_spec(raw: str) -> List[str]:
    """Parse the --qa-owasp argument into a list of normalized IDs."""

    out: List[str] = []
    seen: set[str] = set()
    for tok in parse_csv(raw):
        for oid in _expand_owasp_token(tok):
            if not oid:
                continue
            if oid not in seen:
                seen.add(oid)
                out.append(oid)
    return out


def _qa_target_owasp_ids(args: argparse.Namespace) -> List[str]:
    """Return the OWASP ids included by this QA run."""

    raw = str(getattr(args, "qa_owasp", "") or "").strip()
    if raw:
        ids = _parse_qa_owasp_spec(raw)
        if ids:
            return ids

    scope = str(getattr(args, "qa_scope", "smoke") or "smoke").lower()
    if scope == "full":
        return [f"A{i:02d}" for i in range(1, 11)]

    # Default: smoke slice.
    return ["A03", "A07"]


def _qa_parse_case_selectors(raw: Optional[str]) -> List[str]:
    return [s for s in parse_csv(raw or "") if s]


def _qa_matches_selector(value: str, selector: str) -> bool:
    """Match a selector against a value.

    If selector contains glob metacharacters (*, ?, [), uses fnmatch.
    Otherwise does a case-insensitive substring match.
    """

    v = (value or "").lower()
    s = (selector or "").strip().lower()
    if not s:
        return False
    if any(ch in s for ch in ("*", "?", "[")):
        return fnmatch.fnmatch(v, s)
    return s in v


def _infer_case_owasp_id(sc: SuiteCase) -> Optional[str]:
    c = sc.case
    return _detect_owasp_id(c.case_id, c.branch, c.label)


def _filter_suite_def_for_qa(
    suite_def: SuiteDefinition,
    *,
    selectors: List[str],
    wanted_owasp_ids: List[str],
) -> SuiteDefinition:
    """Return a suite definition restricted to the QA slice."""

    selected: List[SuiteCase] = []
    skipped: List[SuiteCase] = []

    if selectors:
        for sc in suite_def.cases:
            c = sc.case
            hay = [str(c.case_id or ""), str(c.branch or ""), str(c.label or "")]
            if any(_qa_matches_selector(v, sel) for sel in selectors for v in hay):
                selected.append(sc)
            else:
                skipped.append(sc)
        reason = f"selectors: {', '.join(selectors)}"
    else:
        targets = set(wanted_owasp_ids)
        for sc in suite_def.cases:
            owasp = _infer_case_owasp_id(sc)
            if owasp and owasp in targets:
                selected.append(sc)
            else:
                skipped.append(sc)
        reason = f"OWASP IDs: {', '.join(sorted(targets))}"

    if not selected:
        raise SystemExit(
            "QA calibration slice matched 0 cases. "
            "Either pass --qa-cases (explicit selectors) or ensure case_id/branch/label contains an OWASP id like 'A03'."
        )

    # Deterministic ordering.
    selected.sort(key=lambda sc: str(sc.case.case_id))

    print("\n🧪 QA calibration slice")
    print(f"   - {reason}")
    print(f"   - selected {len(selected)} case(s); skipped {len(skipped)}")

    return SuiteDefinition(suite_id=suite_def.suite_id, scanners=suite_def.scanners, cases=selected, analysis=suite_def.analysis)


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

    # ------------------------------------------------------------------
    # QA calibration runbook: deterministic two-pass execution
    # ------------------------------------------------------------------
    qa_mode = bool(getattr(args, "qa_calibration", False))
    qa_no_reanalyze = bool(getattr(args, "qa_no_reanalyze", False))

    # Capture GT tolerance input *before* any sweep/auto-selection mutates args.
    gt_tolerance_initial = int(getattr(args, "gt_tolerance", 0) or 0)

    # Best-effort capture of sweep/auto state for a QA manifest.
    # (Written at the end of the runbook when suite_id/suite_dir are finalized.)
    gt_sweep_enabled = False
    gt_sweep_candidates: List[int] = []
    gt_sweep_report_csv: Optional[str] = None
    gt_sweep_payload_json: Optional[str] = None
    gt_selection_path: Optional[str] = None
    gt_selection_warnings: List[str] = []

    # Captured (best-effort) sweep payload + selection decision for later writing
    # to analysis/gt_tolerance_selection.json (and for the QA manifest).
    gt_sweep_payload = None
    gt_tolerance_selection = None

    qa_checklist_pass: Optional[bool] = None
    if qa_mode:
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

    # Load or build suite definition
    # Load suite definition (Python only at runtime; YAML is migration-only)
    # ------------------------------------------------------------------
    # Bridge path: bootstrap worktrees from --repo-url + --branches
    #
    # Suite mode typically expects local checkouts (worktrees) to already exist.
    # When the user provides a repo URL and a branch set, we can create/update
    # a deterministic worktrees root and then load cases from it.
    #
    # In QA mode, branches default to the requested QA slice (A03/A07 or A01..A10).
    # ------------------------------------------------------------------
    if getattr(args, "repo_url", None) and (not args.suite_file) and (not args.cases_from):
        branches = _parse_branches_spec(getattr(args, "branches", None))
        if qa_mode and not branches:
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

        if qa_mode:
            print(f"🧪 QA calibration: bootstrapped worktrees-root: {wt_root}")
        else:
            print(f"🌿 Suite worktrees ready: {wt_root}")

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

    # QA case selection: restrict the suite to the requested OWASP slice.
    if qa_mode:
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
            found_ids = sorted({
                _detect_owasp_id(sc.case.case_id, sc.case.branch, sc.case.label)
                for sc in suite_def.cases
                if _detect_owasp_id(sc.case.case_id, sc.case.branch, sc.case.label)
            })
            print(
                "❌ QA calibration selection produced 0 cases.\n"
                f"Requested scope: {scope_label} (targets={sorted(targets)})\n"
                f"Found OWASP ids in suite: {found_ids}\n"
                "Tip: use --qa-owasp to override or point --cases-from/--worktrees-root at a suite with OWASP-labelled cases."
            )
            return 2

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

    if qa_mode and skip_analysis:
        print("❌ --qa-calibration cannot run with analysis skipped (suite_def.analysis.skip / --skip-analysis).")
        return 2

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
        suite_kind="qa_calibration" if qa_mode else "benchmark",
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

        rc_code = int(pipeline.run(req))
        overall = max(overall, rc_code)



    # ------------------------------------------------------------------
    # Suite-level aggregation: triage dataset (+ optional gt_tolerance sweep)
    # ------------------------------------------------------------------
    # This is intentionally filesystem-first and best-effort.
    # If some cases are missing triage_features.csv (analysis skipped/failed),
    # the builder will log them explicitly.
    if (not bool(args.dry_run)) and (not bool(skip_analysis)):

        # Optional deterministic GT tolerance sweep (QA calibration).
        #
        # Why this lives here:
        # - We want to reuse the existing per-case analyze pipeline.
        # - We want suite-level dataset/calibration/eval snapshots per tolerance.
        # - We cannot prompt in CI, so selection (when enabled) must be deterministic.
        sweep_raw = getattr(args, "gt_tolerance_sweep", None)
        sweep_auto = bool(getattr(args, "gt_tolerance_auto", False))
        sweep_min_frac = float(getattr(args, "gt_tolerance_auto_min_fraction", 0.95) or 0.95)

        if qa_mode and (sweep_raw or sweep_auto):
            # Mark as "requested" immediately so the QA manifest can record intent
            # even if the sweep fails early.
            gt_sweep_enabled = True
            gt_sweep_report_csv = str((suite_dir / "analysis" / "_tables" / "gt_tolerance_sweep_report.csv").resolve())
            gt_sweep_payload_json = str((suite_dir / "analysis" / "gt_tolerance_sweep.json").resolve())

            try:
                from pipeline.analysis.gt_tolerance_sweep import (
                    disable_suite_calibration,
                    parse_gt_tolerance_candidates,
                    run_gt_tolerance_sweep,
                    select_gt_tolerance_auto,
                )

                candidates = parse_gt_tolerance_candidates(sweep_raw)

                gt_sweep_candidates = list(candidates)

                sweep_payload = run_gt_tolerance_sweep(
                    pipeline=pipeline,
                    suite_root=suite_root,
                    suite_id=suite_id,
                    suite_dir=suite_dir,
                    cases=[rc.suite_case.case for rc in resolved_run.cases],
                    tools=scanners,
                    tolerance=int(tolerance),
                    gt_source=str(getattr(args, "gt_source", "auto")),
                    analysis_filter=str(analysis_filter),
                    exclude_prefixes=getattr(args, "exclude_prefixes", ()) or (),
                    include_harness=bool(getattr(args, "include_harness", False)),
                    candidates=candidates,
                )

                # Record the emitted report path (should match the canonical path).
                gt_sweep_report_csv = str(sweep_payload.get("out_report_csv") or gt_sweep_report_csv)

                # Persist sweep payload for later selection/manifest writing.
                gt_sweep_payload = sweep_payload

                if sweep_auto:
                    sel = select_gt_tolerance_auto(
                        sweep_payload.get("rows") or [],
                        min_fraction=sweep_min_frac,
                    )
                    chosen = int(sel.get("selected_gt_tolerance", int(getattr(args, "gt_tolerance", 0))))

                    # Record decision (we write the selection file later so the QA checklist
                    # can enforce it regardless of auto vs explicit selection).
                    gt_tolerance_selection = dict(sel)
                    gt_selection_warnings = [str(w) for w in (sel.get("warnings") or []) if str(w).strip()]

                    print(f"\n✅ GT tolerance auto-selected: {chosen}")
                    if gt_selection_warnings:
                        for w in gt_selection_warnings:
                            print(f"  ⚠️  {w}")

                    # Make downstream steps (final build + re-analyze pass) use the chosen tolerance.
                    try:
                        setattr(args, "gt_tolerance", chosen)
                    except Exception:
                        pass
                else:
                    # Explicit tolerance path: still record for CI reproducibility.
                    gt_tolerance_selection = {
                        "schema_version": "gt_tolerance_selection_v1",
                        "selected_gt_tolerance": int(getattr(args, "gt_tolerance", 0) or 0),
                        "mode": "explicit",
                        "warnings": [],
                    }
                    print("\nℹ️  GT tolerance sweep complete (no auto selection; continuing with --gt-tolerance)")

                # After the sweep, rebuild canonical suite calibration artifacts once
                # for the effective tolerance (explicit or auto-selected).
                eff_tol = int(getattr(args, "gt_tolerance", 0))
                print(f"\n🔁 Finalizing suite calibration build for gt_tolerance={eff_tol}")

                # Ensure per-case analysis uses baseline ordering for triage_rank.
                disable_suite_calibration(suite_dir)

                # Re-analyze all cases once with the chosen tolerance (skip suite aggregation
                # inside each analyze call; we'll build suite artifacts once below).
                for j, rc2 in enumerate(resolved_run.cases, start=1):
                    c2 = rc2.suite_case.case
                    print("\n" + "-" * 72)
                    print(f"🔁 Analyze (finalize) {j}/{len(resolved_run.cases)}: {c2.case_id}")

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
                            gt_tolerance=int(eff_tol),
                            gt_source=str(getattr(args, "gt_source", "auto")),
                            analysis_filter=str(analysis_filter),
                            exclude_prefixes=getattr(args, "exclude_prefixes", ()) or (),
                            include_harness=bool(getattr(args, "include_harness", False)),
                            skip_suite_aggregate=True,
                        )
                        rc_code2 = int(pipeline.analyze(areq))
                    except Exception as e:
                        print(f"  ❌ analyze finalize failed for {c2.case_id}: {e}")
                        rc_code2 = 2

                    overall = max(overall, rc_code2)

            except Exception as e:
                print(f"\n❌ GT tolerance sweep failed: {e}")
                # In QA mode, requested sweeps are first-class; fail the run (but keep going to emit whatever artifacts we can).
                overall = max(overall, 2)
                gt_selection_warnings = list(gt_selection_warnings or []) + [f"sweep_failed: {e}"]

        # From this point on, the rest of the runbook assumes the *effective*
        # gt_tolerance has been applied (either explicit or auto-selected).
        try:
            from pipeline.analysis.suite_triage_dataset import build_triage_dataset

            ds = build_triage_dataset(suite_dir=suite_dir, suite_id=suite_id)

            print("\n📦 Suite triage_dataset")
            print(f"  Output : {ds.get('out_csv')}")
            print(f"  Rows   : {ds.get('rows')}")

            if ds.get("missing_cases"):
                missing = ds.get("missing_cases") or []
                print(
                    f"  ⚠️  Missing triage_features.csv for {len(missing)} case(s): "
                    + ", ".join([str(x) for x in missing])
                )

            if ds.get("empty_cases"):
                empty = ds.get("empty_cases") or []
                print(
                    f"  ⚠️  Empty triage_features.csv for {len(empty)} case(s): "
                    + ", ".join([str(x) for x in empty])
                )

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

        # ------------------------------------------------------------------
        # Suite-level calibration: tool weights for triage tie-breaking
        # ------------------------------------------------------------------
        # This is a best-effort step. If GT is missing for many cases, the
        # calibration builder will exclude those cases explicitly.
        try:
            from pipeline.analysis.suite_triage_calibration import build_triage_calibration

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

        # ------------------------------------------------------------------
        # Suite-level evaluation: triage ranking quality + tool utility
        # ------------------------------------------------------------------
        try:
            from pipeline.analysis.suite_triage_eval import build_triage_eval

            ev = build_triage_eval(suite_dir=suite_dir, suite_id=suite_id)

            print("\n📈 Suite triage_eval")
            print(f"  Summary : {ev.get('out_summary_json')}")
            print(f"  By-case : {ev.get('out_by_case_csv')}")
            print(f"  Tools   : {ev.get('out_tool_utility_csv')}")

            # Drop-one tool marginal value table (if computed). This is the
            # most direct answer to: "what happens if we remove tool X?".
            # It is optional because callers may disable tool-marginal during
            # expensive sweeps.
            if ev.get("out_tool_marginal_csv"):
                print(f"  Marginal: {ev.get('out_tool_marginal_csv')}")

            # Print a compact macro snapshot for Ks that matter for triage (top-1/top-3/top-5).
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
                    rc_code2 = int(pipeline.analyze(areq))
                except Exception as e:
                    print(f"  ❌ re-analyze failed for {c2.case_id}: {e}")
                    rc_code2 = 2

                overall = max(overall, rc_code2)

        # PASS/FAIL checklist
        # Write GT tolerance selection/policy artifact for CI reproducibility.
        #
        # This is required in QA mode so that CI can recover the effective
        # gt_tolerance (explicit vs sweep vs auto) without parsing stdout.
        try:
            from pipeline.analysis.gt_tolerance_sweep import write_gt_tolerance_selection

            eff_tol = int(getattr(args, "gt_tolerance", 0) or 0)

            selection = dict(gt_tolerance_selection or {}) if isinstance(gt_tolerance_selection, dict) else {}
            if not selection:
                selection = {
                    "schema_version": "gt_tolerance_selection_v1",
                    "selected_gt_tolerance": int(eff_tol),
                    "mode": "explicit",
                    "warnings": [],
                }

            # Always update to the effective tolerance at the time of writing.
            selection["selected_gt_tolerance"] = int(eff_tol)

            # Record the policy inputs that influence selection (small + stable).
            selection.setdefault("policy", {})
            selection["policy"].update(
                {
                    "initial_gt_tolerance": int(gt_tolerance_initial),
                    "effective_gt_tolerance": int(eff_tol),
                    "sweep_raw": str(sweep_raw) if sweep_raw is not None else None,
                    "sweep_candidates": [int(x) for x in (gt_sweep_candidates or [])] if bool(gt_sweep_enabled) else [],
                    "auto_enabled": bool(sweep_auto),
                    "auto_min_fraction": float(sweep_min_frac) if bool(sweep_auto) else None,
                    "gt_source": str(getattr(args, "gt_source", "auto")),
                }
            )

            out_sel = write_gt_tolerance_selection(
                suite_dir=suite_dir,
                selection=selection,
                sweep_payload=gt_sweep_payload,
            )
            gt_selection_path = str(out_sel)
            print(f"\n🧾 Wrote GT tolerance selection: {out_sel}")
        except Exception as e:
            print(f"\n❌ Failed to write GT tolerance selection file: {e}")
            overall = max(overall, 2)

        try:
            from pipeline.analysis.qa_calibration_runbook import (
                all_ok,
                render_checklist,
                validate_calibration_suite_artifacts,
            )

            checks = validate_calibration_suite_artifacts(
                suite_dir=suite_dir,
                require_scored_queue=(not qa_no_reanalyze),
                expect_calibration=True,
                expect_gt_tolerance_sweep=bool(sweep_raw or sweep_auto),
                expect_gt_tolerance_selection=True,
            )
            qa_checklist_pass = bool(all_ok(checks))
            report = render_checklist(checks, title="QA calibration checklist")
            print(report)

            # Write next to other suite-level analysis artifacts for CI scraping.
            try:
                out_path = (suite_dir / "analysis" / "qa_calibration_checklist.txt").resolve()
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(report, encoding="utf-8")
                print(f"\n📝 Wrote checklist: {out_path}")
            except Exception as e:
                print(f"\n⚠️  Failed to write checklist file: {e}")

            if not all_ok(checks):
                overall = max(overall, 2)
        except Exception as e:
            print(f"\n❌ QA calibration validation failed: {e}")
            overall = max(overall, 2)

        # QA manifest (best-effort). Write even on FAIL for CI scraping.
        try:
            from pipeline.analysis.qa_calibration_manifest import (
                GTTolerancePolicyRecord,
                build_qa_calibration_manifest,
                write_qa_calibration_manifest,
            )

            # Canonical artifact locations (relative paths are normalized in the writer).
            artifacts = {
                "triage_dataset_csv": str((suite_dir / "analysis" / "_tables" / "triage_dataset.csv").resolve()),
                "triage_calibration_json": str((suite_dir / "analysis" / "triage_calibration.json").resolve()),
                "triage_eval_summary_json": str((suite_dir / "analysis" / "_tables" / "triage_eval_summary.json").resolve()),
                # Tool contribution / marginal value (suite-level)
                # These are produced by build_triage_eval and are the most
                # recruiter-friendly "ROI" outputs:
                # - triage_tool_utility: unique GT coverage vs exclusive noise
                # - triage_tool_marginal: drop-one deltas (remove tool X)
                "triage_tool_utility_csv": str((suite_dir / "analysis" / "_tables" / "triage_tool_utility.csv").resolve()),
                "triage_tool_marginal_csv": str((suite_dir / "analysis" / "_tables" / "triage_tool_marginal.csv").resolve()),
                "qa_checklist_txt": str((suite_dir / "analysis" / "qa_calibration_checklist.txt").resolve()),
                "gt_tolerance_selection_json": gt_selection_path,
            }

            if gt_sweep_enabled:
                artifacts.update(
                    {
                        "gt_tolerance_sweep_report_csv": gt_sweep_report_csv,
                        "gt_tolerance_sweep_payload_json": gt_sweep_payload_json,
                        "gt_tolerance_sweep_tool_stats_csv": str(
                            (suite_dir / "analysis" / "_tables" / "gt_tolerance_sweep_tool_stats.csv").resolve()
                        ),
                    }
                )

            gt_policy = GTTolerancePolicyRecord(
                initial_gt_tolerance=int(gt_tolerance_initial),
                effective_gt_tolerance=int(getattr(args, "gt_tolerance", 0) or 0),
                sweep_enabled=bool(gt_sweep_enabled),
                sweep_candidates=[int(x) for x in (gt_sweep_candidates or [])],
                auto_enabled=bool(getattr(args, "gt_tolerance_auto", False)),
                auto_min_fraction=float(getattr(args, "gt_tolerance_auto_min_fraction", 0.95) or 0.95)
                if bool(getattr(args, "gt_tolerance_auto", False))
                else None,
                selection_path=gt_selection_path,
                sweep_report_csv=gt_sweep_report_csv,
                sweep_payload_json=gt_sweep_payload_json,
                selection_warnings=list(gt_selection_warnings or []),
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
                checklist_pass=qa_checklist_pass,
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
    print("\n✅ Suite complete")
    print(f"  Suite id : {suite_id}")
    print(f"  Suite dir: {suite_dir}")
    return overall
