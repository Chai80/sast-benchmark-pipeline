"""pipeline.analysis.gt_scorer

Ground-truth (GT) scoring for the Durinn OWASP 2021 Python micro-suite.

What this does
--------------
Given:
  - Normalized scanner outputs (common schema v1.1)
  - A micro-suite GT catalog (benchmark/gt_catalog.yaml)
  - A suite set definition (benchmark/suite_sets.yaml)

This module computes *location-based* matches between tool findings and the
expected GT items for a single micro-suite branch (case). It produces:

  - TP / FN per GT id (for the chosen branch)
  - FP set (findings that don't map to any GT id for the branch)
  - Separate scorecards for:
      * core_sast_intersection
      * extended_sast
      * out_of_scope_for_sast (reported but not counted in SAST score)

Important limitations
---------------------
- This is *not* a semantic proof. It matches by (file_path, line range).
- GT scoring assumes you are scanning the intended branch and that the GT
  catalog line ranges correspond to that branch's code.
- SCA track (A06) is not GT-scored here because that branch uses dependency
  CVEs rather than code-location markers.

Usage (case-level)
------------------
Run this *after* scans, against a suite case directory:

  python -m pipeline.analysis.gt_scorer \
    --case-dir runs/suites/<SUITE_ID>/cases/<BRANCH_NAME> \
    --gt-catalog /path/to/micro-suite/benchmark/gt_catalog.yaml \
    --suite-sets /path/to/micro-suite/benchmark/suite_sets.yaml \
    --tools semgrep,snyk,sonar,aikido

Usage (suite-level)
-------------------
Score all cases under a suite directory:

  python -m pipeline.analysis.gt_scorer \
    --suite-dir runs/suites/<SUITE_ID> \
    --gt-catalog /path/to/micro-suite/benchmark/gt_catalog.yaml \
    --suite-sets /path/to/micro-suite/benchmark/suite_sets.yaml
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from pipeline.analysis.finding_filters import filter_findings
from pipeline.analysis.io_utils import load_json, write_csv, write_json
from pipeline.analysis.meta_utils import with_standard_meta
from pipeline.analysis.path_normalization import normalize_file_path
from pipeline.analysis.run_discovery import discover_latest_runs

_yaml_import_error: Optional[str] = None
try:
    import yaml  # type: ignore
except Exception as _e:  # pragma: no cover
    yaml = None  # type: ignore
    _yaml_import_error = repr(_e)


# -------------------------
# Types
# -------------------------

@dataclass(frozen=True)
class FindingLoc:
    file_path: Optional[str]
    line_start: Optional[int]
    line_end: Optional[int]


@dataclass(frozen=True)
class Finding:
    finding_id: str
    rule_id: Optional[str]
    title: Optional[str]
    severity: Optional[str]
    loc: FindingLoc
    raw: Mapping[str, Any]


@dataclass(frozen=True)
class GTItem:
    gt_id: str
    branch: str
    owasp: str
    track: str
    set_name: str
    file_path: str
    start_line: int
    end_line: int
    title: Optional[str]


# -------------------------
# YAML loaders
# -------------------------

def _load_yaml(path: Path) -> Dict[str, Any]:
    if yaml is None:
        msg = (
            "PyYAML is required for GT scoring.\n"
            "Install it with: pip install pyyaml\n"
        )
        if _yaml_import_error:
            msg += f"Import error: {_yaml_import_error}\n"
        raise SystemExit(msg)

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))  # type: ignore[attr-defined]
    except Exception as ex:
        raise SystemExit(f"Failed to parse YAML: {path} ({ex})") from ex

    return data if isinstance(data, dict) else {}


def load_gt_catalog(gt_catalog_path: Path) -> Dict[str, GTItem]:
    data = _load_yaml(gt_catalog_path)
    items = data.get("items")
    if not isinstance(items, list):
        raise SystemExit(f"gt_catalog.yaml missing 'items' list: {gt_catalog_path}")

    out: Dict[str, GTItem] = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        gid = str(it.get("id") or "").strip()
        if not gid:
            continue

        try:
            out[gid] = GTItem(
                gt_id=gid,
                branch=str(it.get("branch") or "").strip(),
                owasp=str(it.get("owasp") or "").strip(),
                track=str(it.get("track") or "").strip(),
                set_name=str(it.get("set") or "").strip(),
                file_path=str(it.get("file") or "").strip(),
                start_line=int(it.get("start_line") or 0),
                end_line=int(it.get("end_line") or 0),
                title=str(it.get("title") or "").strip() or None,
            )
        except Exception as ex:
            raise SystemExit(f"Invalid GT item for id={gid}: {ex}") from ex

    if not out:
        raise SystemExit(f"No GT items loaded from: {gt_catalog_path}")

    return out


def load_suite_sets(suite_sets_path: Path) -> Dict[str, Dict[str, List[str]]]:
    """Return mapping: track -> set_name -> gt_ids list."""
    data = _load_yaml(suite_sets_path)
    tracks = data.get("tracks")
    if not isinstance(tracks, dict):
        return {}

    out: Dict[str, Dict[str, List[str]]] = {}
    for track_name, track_obj in tracks.items():
        if not isinstance(track_obj, dict):
            continue
        sets: Dict[str, List[str]] = {}
        for set_name, set_obj in track_obj.items():
            if not isinstance(set_obj, dict):
                continue
            gt_ids = set_obj.get("gt_ids")
            if isinstance(gt_ids, list):
                sets[str(set_name)] = [str(x).strip() for x in gt_ids if str(x).strip()]
        if sets:
            out[str(track_name)] = sets
    return out


# -------------------------
# Normalized finding parsing
# -------------------------

def _as_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        n = int(v)
        return n if n > 0 else None
    except Exception:
        return None


def parse_findings(
    normalized_json: Mapping[str, Any],
    *,
    tool: str,
    repo_name_for_paths: Optional[str],
    filter_mode: str,
) -> List[Finding]:
    raw_findings = normalized_json.get("findings")
    if not isinstance(raw_findings, list):
        return []

    # Apply the same filter semantics as other analysis stages.
    filtered = filter_findings(tool, raw_findings, mode=filter_mode)

    out: List[Finding] = []
    for f in filtered:
        if not isinstance(f, dict):
            continue

        fid = str(f.get("finding_id") or "").strip() or "unknown"
        file_path_raw = f.get("file_path")
        file_path = normalize_file_path(str(file_path_raw), repo_name_for_paths) if file_path_raw else None

        line_start = _as_int(f.get("line_number"))
        line_end = _as_int(f.get("end_line_number")) or line_start

        out.append(
            Finding(
                finding_id=fid,
                rule_id=str(f.get("rule_id") or "").strip() or None,
                title=str(f.get("title") or "").strip() or None,
                severity=str(f.get("severity") or "").strip() or None,
                loc=FindingLoc(file_path=file_path, line_start=line_start, line_end=line_end),
                raw=f,
            )
        )
    return out


# -------------------------
# Matching logic
# -------------------------

def _ranges_overlap(a0: int, a1: int, b0: int, b1: int) -> bool:
    return a0 <= b1 and b0 <= a1


def _match_one_file(
    *,
    gt_items: Sequence[GTItem],
    findings: Sequence[Finding],
    tolerance: int,
) -> Tuple[Dict[str, Finding], List[Finding]]:
    """Greedy 1:1 matching within a file.

    Returns
    -------
    matches: gt_id -> Finding
    unused_findings: findings not used by any GT match (but still in same file)
    """
    used: set[str] = set()
    matches: Dict[str, Finding] = {}

    # Sort GT by location for stability.
    gt_sorted = sorted(gt_items, key=lambda g: (g.start_line, g.end_line, g.gt_id))

    for gt in gt_sorted:
        gt0 = max(1, gt.start_line - tolerance)
        gt1 = gt.end_line + tolerance

        best: Optional[Finding] = None
        best_dist: Optional[int] = None

        for f in findings:
            if f.finding_id in used:
                continue
            if f.loc.line_start is None or f.loc.line_end is None:
                continue

            if not _ranges_overlap(gt0, gt1, f.loc.line_start, f.loc.line_end):
                continue

            # Distance: how close the finding start is to the GT range start.
            dist = abs(f.loc.line_start - gt.start_line)
            if best is None or (best_dist is not None and dist < best_dist):
                best = f
                best_dist = dist

        if best is not None:
            matches[gt.gt_id] = best
            used.add(best.finding_id)

    unused = [f for f in findings if f.finding_id not in used]
    return matches, unused


def match_findings_to_gt(
    *,
    expected_gt: Sequence[GTItem],
    findings: Sequence[Finding],
    tolerance: int,
) -> Tuple[Dict[str, Finding], List[Finding], List[Finding]]:
    """Match findings to expected GT items.

    Returns
    -------
    matches: gt_id -> Finding
    fp_located: findings with (file + line) that weren't used
    fp_unlocatable: findings missing file or line
    """
    # Group GT + findings by file.
    gt_by_file: Dict[str, List[GTItem]] = defaultdict(list)
    for gt in expected_gt:
        gt_by_file[gt.file_path].append(gt)

    findings_by_file: Dict[str, List[Finding]] = defaultdict(list)
    fp_unlocatable: List[Finding] = []
    for f in findings:
        if not f.loc.file_path or f.loc.line_start is None:
            fp_unlocatable.append(f)
            continue
        findings_by_file[f.loc.file_path].append(f)

    matches: Dict[str, Finding] = {}
    fp_located: List[Finding] = []

    # Match per file.
    for file_path, gt_items in gt_by_file.items():
        file_findings = findings_by_file.get(file_path, [])
        m, unused = _match_one_file(gt_items=gt_items, findings=file_findings, tolerance=tolerance)
        matches.update(m)
        fp_located.extend(unused)

    # Findings in files that have no GT items are also FP.
    gt_files = set(gt_by_file.keys())
    for file_path, file_findings in findings_by_file.items():
        if file_path not in gt_files:
            fp_located.extend(file_findings)

    # De-dup fp lists (by finding_id) in case they got added twice.
    def _dedup(findings_list: List[Finding]) -> List[Finding]:
        seen: set[str] = set()
        out: List[Finding] = []
        for f in findings_list:
            if f.finding_id in seen:
                continue
            seen.add(f.finding_id)
            out.append(f)
        return out

    return matches, _dedup(fp_located), _dedup(fp_unlocatable)


# -------------------------
# Scoring
# -------------------------

def _ids_for_branch(gt_ids: Sequence[str], gt_catalog: Mapping[str, GTItem], branch: str) -> List[str]:
    out: List[str] = []
    for gid in gt_ids:
        item = gt_catalog.get(gid)
        if item and item.branch == branch:
            out.append(gid)
    return out


def score_case(
    *,
    case_dir: Path,
    gt_catalog: Mapping[str, GTItem],
    suite_sets: Mapping[str, Mapping[str, List[str]]],
    tools: Sequence[str],
    tolerance: int,
    filter_mode: str,
    explicit_branch: Optional[str] = None,
    explicit_repo_name: Optional[str] = None,
) -> Dict[str, Any]:
    tool_runs_dir = case_dir / "tool_runs"
    scans_dir = case_dir / "scans"
    runs_root = tool_runs_dir if tool_runs_dir.exists() else scans_dir

    analysis_dir = case_dir / "analysis"
    gt_dir = case_dir / "gt"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    gt_dir.mkdir(parents=True, exist_ok=True)

    branch = explicit_branch or case_dir.name

    # Infer repo_name from scans layout (or default to case name).
    repo_name = explicit_repo_name
    if not repo_name:
        candidates: List[str] = []
        for tool in tools:
            td = runs_root / tool
            if not td.exists():
                continue
            for p in td.iterdir():
                if p.is_dir() and not re.match(r"^\d{10}$", p.name):
                    candidates.append(p.name)
        if candidates:
            repo_name = Counter(candidates).most_common(1)[0][0]
        else:
            repo_name = case_dir.name

    # Expected ids per set for this branch.
    sast_sets = suite_sets.get("sast", {})
    core_ids = _ids_for_branch(sast_sets.get("core_sast_intersection", []), gt_catalog, branch)
    ext_ids = _ids_for_branch(sast_sets.get("extended_sast", []), gt_catalog, branch)
    oos_ids = _ids_for_branch(sast_sets.get("out_of_scope_for_sast", []), gt_catalog, branch)

    expected_core = [gt_catalog[i] for i in core_ids]
    expected_ext = [gt_catalog[i] for i in ext_ids]
    expected_oos = [gt_catalog[i] for i in oos_ids]

    expected_all_scored = expected_core + expected_ext
    expected_all_with_oos = expected_all_scored + expected_oos

    # Discover latest normalized outputs within this case.
    runs = discover_latest_runs(runs_dir=runs_root, repo_name=repo_name, tools=tools, allow_missing=True)

    tools_out: Dict[str, Any] = {}

    for tool in tools:
        run = runs.get(tool)
        if not run:
            tools_out[tool] = {
                "present": False,
                "error": "missing_normalized_json",
            }
            continue

        norm = load_json(run.normalized_json)
        findings = parse_findings(norm, tool=tool, repo_name_for_paths=repo_name, filter_mode=filter_mode)

        matches_all, fp_located, fp_unlocatable = match_findings_to_gt(
            expected_gt=expected_all_with_oos,
            findings=findings,
            tolerance=tolerance,
        )

        matched_ids = set(matches_all.keys())
        matched_core = [gid for gid in core_ids if gid in matched_ids]
        matched_ext = [gid for gid in ext_ids if gid in matched_ids]
        matched_oos = [gid for gid in oos_ids if gid in matched_ids]

        def _set_summary(expected_ids: List[str], matched_ids_list: List[str]) -> Dict[str, Any]:
            exp = len(expected_ids)
            tp = len(matched_ids_list)
            fn = exp - tp
            recall = (tp / exp) if exp > 0 else None
            return {"expected": exp, "tp": tp, "fn": fn, "recall": recall}

        # Precision is computed only on *scored* sets (core+extended).
        scored_expected_ids = core_ids + ext_ids
        scored_tp = len([gid for gid in scored_expected_ids if gid in matched_ids])

        fp_count = len(fp_located)  # located findings not mapped to any GT id (incl oos)
        precision = (scored_tp / (scored_tp + fp_count)) if (scored_tp + fp_count) > 0 else None
        recall_scored = (scored_tp / len(scored_expected_ids)) if len(scored_expected_ids) > 0 else None

        f1 = None
        if precision is not None and recall_scored is not None and (precision + recall_scored) > 0:
            f1 = 2 * precision * recall_scored / (precision + recall_scored)

        # Keep FP payload small.
        def _fp_row(f: Finding) -> Dict[str, Any]:
            return {
                "finding_id": f.finding_id,
                "rule_id": f.rule_id,
                "severity": f.severity,
                "file_path": f.loc.file_path,
                "line": f.loc.line_start,
                "title": f.title,
            }

        tools_out[tool] = {
            "present": True,
            "run": {
                "run_id": run.run_id,
                "scan_date": run.scan_date,
                "commit": run.commit,
                "normalized_json": str(run.normalized_json),
            },
            "summary": {
                "branch": branch,
                "repo_name": repo_name,
                "tolerance": tolerance,
                "filter_mode": filter_mode,
                "scored_expected": len(scored_expected_ids),
                "tp": scored_tp,
                "fn": len(scored_expected_ids) - scored_tp,
                "fp_located": fp_count,
                "fp_unlocatable": len(fp_unlocatable),
                "precision": precision,
                "recall": recall_scored,
                "f1": f1,
            },
            "sets": {
                "core_sast_intersection": _set_summary(core_ids, matched_core),
                "extended_sast": _set_summary(ext_ids, matched_ext),
                "out_of_scope_for_sast": _set_summary(oos_ids, matched_oos),
            },
            "matched_gt_ids": sorted(list(matched_ids)),
            "fn_gt_ids": sorted([gid for gid in scored_expected_ids if gid not in matched_ids]),
            "fp_located": [_fp_row(f) for f in fp_located[:200]],
            "fp_located_total": fp_count,
            "fp_unlocatable": [_fp_row(f) for f in fp_unlocatable[:200]],
            "fp_unlocatable_total": len(fp_unlocatable),
            "matches": {
                gid: {
                    "finding_id": f.finding_id,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "file_path": f.loc.file_path,
                    "line": f.loc.line_start,
                    "title": f.title,
                }
                for gid, f in matches_all.items()
            },
        }

    report: Dict[str, Any] = {
        "meta": with_standard_meta(
            None,
            stage="gt_scoring",
            repo=repo_name,
            tool_names=list(tools),
            case_dir=str(case_dir),
        ),
        "case": {
            "case_dir": str(case_dir),
            "branch": branch,
            "repo_name": repo_name,
            "tolerance": tolerance,
            "filter_mode": filter_mode,
        },
        "gt": {
            "gt_catalog_items": len(gt_catalog),
            "expected": {
                "core_sast_intersection": core_ids,
                "extended_sast": ext_ids,
                "out_of_scope_for_sast": oos_ids,
            },
        },
        "tools": tools_out,
    }

    # Default outputs in the case analysis dir.
    out_json = gt_dir / "gt_score.json"
    out_csv = gt_dir / "gt_score.csv"

    write_json(report, out_json)

    # CSV: one row per tool
    rows: List[Dict[str, Any]] = []
    for tool in tools:
        t = tools_out.get(tool) or {}
        if not t.get("present"):
            rows.append({"tool": tool, "present": False, "error": t.get("error")})
            continue
        s = t.get("summary") or {}
        rows.append({"tool": tool, "present": True, **s})
    write_csv(rows, out_csv)

    return report


def score_suite(
    *,
    suite_dir: Path,
    gt_catalog: Mapping[str, GTItem],
    suite_sets: Mapping[str, Mapping[str, List[str]]],
    tools: Sequence[str],
    tolerance: int,
    filter_mode: str,
) -> Dict[str, Any]:
    cases_dir = suite_dir / "cases"
    if not cases_dir.exists():
        raise SystemExit(f"Suite dir does not look valid (missing cases/): {suite_dir}")

    case_dirs = sorted([p for p in cases_dir.iterdir() if p.is_dir()], key=lambda p: p.name)

    suite_rows: List[Dict[str, Any]] = []

    for case_dir in case_dirs:
        rep = score_case(
            case_dir=case_dir,
            gt_catalog=gt_catalog,
            suite_sets=suite_sets,
            tools=tools,
            tolerance=tolerance,
            filter_mode=filter_mode,
            explicit_branch=case_dir.name,
            explicit_repo_name=None,
        )

        # flatten tool summaries to one row per (case, tool)
        tools_obj = rep.get("tools") or {}
        for tool in tools:
            t = tools_obj.get(tool) or {}
            if not t.get("present"):
                suite_rows.append(
                    {"case": case_dir.name, "tool": tool, "present": False, "error": t.get("error")}
                )
                continue
            s = t.get("summary") or {}
            suite_rows.append({"case": case_dir.name, "tool": tool, "present": True, **s})

    suite_report: Dict[str, Any] = {
        "meta": with_standard_meta(
            None,
            stage="gt_scoring_suite",
            repo=None,
            tool_names=list(tools),
            suite_dir=str(suite_dir),
        ),
        "suite_dir": str(suite_dir),
        "cases_scored": [p.name for p in case_dirs],
        "rows": suite_rows,
    }

    # Write suite summary files at suite root.
    write_json(suite_report, suite_dir / "gt_summary.json")
    write_csv(suite_rows, suite_dir / "gt_summary.csv")

    return suite_report


# -------------------------
# CLI
# -------------------------

def _parse_csv(raw: str | None) -> List[str]:
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def main() -> None:
    ap = argparse.ArgumentParser(description="GT scoring for the Durinn micro-suite.")
    ap.add_argument("--case-dir", help="Path to a suite case dir (runs/suites/<id>/cases/<case>).")
    ap.add_argument("--suite-dir", help="Path to a suite dir (runs/suites/<id>). If set, scores all cases.")
    ap.add_argument("--gt-catalog", required=True, help="Path to micro-suite benchmark/gt_catalog.yaml")
    ap.add_argument("--suite-sets", required=True, help="Path to micro-suite benchmark/suite_sets.yaml")
    ap.add_argument(
        "--tools",
        default="semgrep,snyk,sonar,aikido",
        help="Comma-separated tools (default: semgrep,snyk,sonar,aikido)",
    )
    ap.add_argument("--tolerance", type=int, default=3, help="Line-range tolerance for matching (default: 3)")
    ap.add_argument(
        "--filter",
        choices=["security", "all"],
        default="security",
        help="Finding filter mode (default: security)",
    )
    ap.add_argument("--branch", help="Explicit micro-suite branch name (defaults to case dir name)")
    ap.add_argument("--repo-name", help="Explicit repo_name under scans/<tool>/<repo_name>/ (defaults to inferred)")
    args = ap.parse_args()

    gt_catalog_path = Path(args.gt_catalog).expanduser().resolve()
    suite_sets_path = Path(args.suite_sets).expanduser().resolve()

    gt_catalog = load_gt_catalog(gt_catalog_path)
    suite_sets = load_suite_sets(suite_sets_path)

    tools = _parse_csv(args.tools)

    if args.suite_dir:
        suite_dir = Path(args.suite_dir).expanduser().resolve()
        score_suite(
            suite_dir=suite_dir,
            gt_catalog=gt_catalog,
            suite_sets=suite_sets,
            tools=tools,
            tolerance=int(args.tolerance),
            filter_mode=str(args.filter),
        )
        return

    if not args.case_dir:
        raise SystemExit("Provide either --case-dir or --suite-dir")

    case_dir = Path(args.case_dir).expanduser().resolve()
    score_case(
        case_dir=case_dir,
        gt_catalog=gt_catalog,
        suite_sets=suite_sets,
        tools=tools,
        tolerance=int(args.tolerance),
        filter_mode=str(args.filter),
        explicit_branch=args.branch,
        explicit_repo_name=args.repo_name,
    )


if __name__ == "__main__":
    main()
