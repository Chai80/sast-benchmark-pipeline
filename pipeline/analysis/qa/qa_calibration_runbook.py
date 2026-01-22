from __future__ import annotations

"""pipeline.analysis.qa_calibration_runbook

Filesystem-first validation helpers for the triage calibration workflow.

Why this exists
---------------
The calibration pipeline is intentionally incremental:

1) Per-case analysis writes triage_features.csv (and triage_queue.csv).
2) Suite-level builders aggregate triage_dataset.csv and triage_calibration.json.
3) Per-case triage queue can optionally be re-analyzed to *apply* calibration
   weights (triage_score_v1 populated).

This module implements a small, deterministic QA checklist that validates the
expected suite artifacts exist under:

  runs/suites/<suite_id>/analysis/

The CLI exposes this via `--mode suite --qa-calibration`.

NOTE: For non-scored suites (no GT), some calibration artifacts may be empty or
not meaningful. See docs/triage_calibration.md for guidance.
"""

import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pipeline.analysis.io.write_artifacts import write_json
from pipeline.analysis.io.config_receipts import summarize_scanner_config


QA_CHECKLIST_SCHEMA_V1 = "qa_checklist_v1"

# Canonical filenames for deterministic CI scraping.
QA_CHECKLIST_JSON_FILENAME = "qa_checklist.json"
QA_CHECKLIST_MD_FILENAME = "qa_checklist.md"

# Backwards-compatible alias for existing scripts/tests.
QA_CHECKLIST_TXT_LEGACY_FILENAME = "qa_calibration_checklist.txt"


@dataclass(frozen=True)
class QACheck:
    """One checklist line item."""

    name: str
    ok: bool
    path: str = ""
    detail: str = ""
    warn: bool = False


def render_checklist(checks: List[QACheck], *, title: str = "QA calibration checklist") -> str:
    """Render a concise PASS/FAIL checklist suitable for CLI output."""

    lines: List[str] = []
    lines.append(f"\n🔎 {title}")
    for c in checks:
        icon = "❌" if (not c.ok) else ("⚠️" if bool(getattr(c, "warn", False)) else "✅")
        lines.append(f"{icon} {c.name}")
        # Show details for failures and warnings.
        if (not c.ok) or bool(getattr(c, "warn", False)):
            if c.path:
                lines.append(f"    path: {c.path}")
            if c.detail:
                lines.append(f"    {c.detail}")

    overall_ok = all(c.ok for c in checks)
    lines.append(f"\nOverall: {'PASS' if overall_ok else 'FAIL'}")
    return "\n".join(lines)


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def checklist_to_dict(
    checks: Sequence[QACheck],
    *,
    suite_dir: str | Path,
    suite_id: Optional[str] = None,
    title: str = "QA calibration checklist",
) -> Dict[str, Any]:
    """Serialize a QA checklist to a stable JSON payload.

    This is intentionally small and filesystem-first. The checklist itself
    *proves what ran* by asserting required artifacts exist.
    """

    sd = Path(suite_dir).resolve()
    sid = str(suite_id) if suite_id else sd.name

    checks_list: List[Dict[str, Any]] = []
    pass_n = 0
    warn_n = 0
    fail_n = 0
    for c in checks:
        ok = bool(c.ok)
        warn = bool(getattr(c, "warn", False))
        if ok and warn:
            warn_n += 1
        elif ok:
            pass_n += 1
        else:
            fail_n += 1

        checks_list.append(
            {
                "name": str(c.name),
                "ok": bool(ok),
                "warn": bool(warn),
                "path": str(c.path or ""),
                "detail": str(c.detail or ""),
            }
        )

    overall_ok = all_ok(checks)

    return {
        "schema_version": QA_CHECKLIST_SCHEMA_V1,
        "generated_at": _now_iso_utc(),
        "title": str(title),
        "suite": {
            "suite_id": sid,
            "suite_dir": str(sd),
        },
        "summary": {
            "overall": "PASS" if overall_ok else "FAIL",
            "overall_ok": bool(overall_ok),
            "checks_total": int(len(checks_list)),
            "pass": int(pass_n),
            "warn": int(warn_n),
            "fail": int(fail_n),
        },
        "checks": checks_list,
    }


def render_checklist_markdown(
    checks: Sequence[QACheck],
    *,
    title: str = "QA calibration checklist",
    suite_dir: Optional[str | Path] = None,
    suite_id: Optional[str] = None,
) -> str:
    """Render a markdown checklist for humans (GitHub-friendly)."""

    sd: Optional[Path] = None
    if suite_dir is not None:
        try:
            sd = Path(suite_dir).resolve()
        except Exception:
            sd = None

    sid = str(suite_id) if suite_id else (sd.name if sd is not None else "")
    overall_ok = all_ok(checks)

    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    if sid:
        lines.append(f"- suite_id: `{sid}`")
    if sd is not None:
        lines.append(f"- suite_dir: `{sd}`")
    lines.append(f"- generated_at: `{_now_iso_utc()}`")
    lines.append(f"- overall: **{'PASS' if overall_ok else 'FAIL'}**")
    lines.append("")

    lines.append("## Checks")
    lines.append("")
    for c in checks:
        ok = bool(c.ok)
        warn = bool(getattr(c, "warn", False))
        icon = "✅" if ok else "❌"
        if ok and warn:
            icon = "⚠️"
        lines.append(f"- {icon} {c.name}")
        if (not ok) or warn:
            if c.path:
                lines.append(f"  - path: `{c.path}`")
            if c.detail:
                lines.append(f"  - detail: {c.detail}")

    lines.append("")
    return "\n".join(lines) + "\n"


def write_qa_checklist_artifacts(
    checks: Sequence[QACheck],
    *,
    suite_dir: str | Path,
    suite_id: Optional[str] = None,
    title: str = "QA calibration checklist",
    out_dirname: str = "analysis",
    json_filename: str = QA_CHECKLIST_JSON_FILENAME,
    md_filename: str = QA_CHECKLIST_MD_FILENAME,
    legacy_txt_filename: str = QA_CHECKLIST_TXT_LEGACY_FILENAME,
) -> Dict[str, str]:
    """Write checklist artifacts under runs/suites/<suite_id>/analysis/.

    Outputs
    -------
    - analysis/qa_checklist.json (canonical, stable for CI)
    - analysis/qa_checklist.md (human-friendly)
    - analysis/qa_calibration_checklist.txt (legacy alias for compatibility)
    """

    sd = Path(suite_dir).resolve()
    sid = str(suite_id) if suite_id else sd.name
    out_dir = (sd / out_dirname).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = checklist_to_dict(checks, suite_dir=sd, suite_id=sid, title=title)
    out_json = (out_dir / json_filename).resolve()
    write_json(out_json, payload)

    md = render_checklist_markdown(checks, title=title, suite_dir=sd, suite_id=sid)
    out_md = (out_dir / md_filename).resolve()
    out_md.write_text(md, encoding="utf-8")

    # Preserve the existing legacy filename used by tests and scripts.
    txt = render_checklist(list(checks), title=title)
    out_txt = (out_dir / legacy_txt_filename).resolve()
    out_txt.write_text(txt, encoding="utf-8")

    return {
        "out_json": str(out_json),
        "out_md": str(out_md),
        "out_txt": str(out_txt),
    }


def all_ok(checks: Sequence[QACheck]) -> bool:
    return all(bool(c.ok) for c in checks)


def print_checklist(checks: Sequence[QACheck]) -> None:
    """Print a compact PASS/FAIL checklist."""

    for c in checks:
        status = "FAIL" if (not c.ok) else ("WARN" if bool(getattr(c, "warn", False)) else "PASS")
        suffix = ""
        if c.path:
            suffix += f"  [{c.path}]"
        if c.detail:
            suffix += ("  " if suffix else "  ") + str(c.detail)
        print(f"  [{status}] {c.name}{suffix}")


def _read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _read_csv_header(path: Path) -> List[str]:
    p = Path(path)
    with p.open("r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, [])
    return [str(h).strip() for h in (header or []) if str(h).strip()]


def _read_csv_dict_rows(path: Path) -> List[Dict[str, str]]:
    p = Path(path)
    with p.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [dict(r) for r in reader if isinstance(r, dict)]


def _parse_json_list(raw: str) -> List[str]:
    s = str(raw or "").strip()
    if not s:
        return []
    try:
        v = json.loads(s)
        if isinstance(v, list):
            return [str(x) for x in v if str(x).strip()]
    except Exception:
        return []
    return []


def _compute_gt_ambiguity_stats(dataset_csv: Path) -> Dict[str, int]:
    """Compute many-to-one / one-to-many ambiguity stats from triage_dataset.csv.

    This intentionally mirrors the sweep's ambiguity counters, but stays local
    to the QA checklist so we can surface warnings even when no sweep ran.
    """

    rows = _read_csv_dict_rows(dataset_csv)

    gt_id_to_cluster_count: Dict[str, int] = {}
    clusters_multi_gt = 0
    max_gt_ids_per_cluster = 0

    for r in rows:
        ids: List[str] = []

        raw_ids_json = str(r.get("gt_overlap_ids_json") or "").strip()
        if raw_ids_json:
            ids = _parse_json_list(raw_ids_json)

        # Fallback: semicolon list
        if not ids:
            raw_ids = str(r.get("gt_overlap_ids") or "").strip()
            if raw_ids:
                ids = [p.strip() for p in raw_ids.split(";") if p.strip()]

        if not ids:
            continue

        uniq = sorted(set(ids))
        if len(uniq) > 1:
            clusters_multi_gt += 1
        max_gt_ids_per_cluster = max(max_gt_ids_per_cluster, len(uniq))
        for gid in uniq:
            gt_id_to_cluster_count[gid] = int(gt_id_to_cluster_count.get(gid, 0)) + 1

    gt_ids_covered = len(gt_id_to_cluster_count)
    gt_ids_multi_cluster = sum(1 for _gid, c in gt_id_to_cluster_count.items() if int(c) > 1)
    max_clusters_per_gt_id = max([int(c) for c in gt_id_to_cluster_count.values()], default=0)

    return {
        "gt_ids_covered": int(gt_ids_covered),
        "clusters_multi_gt": int(clusters_multi_gt),
        "gt_ids_multi_cluster": int(gt_ids_multi_cluster),
        "max_gt_ids_per_cluster": int(max_gt_ids_per_cluster),
        "max_clusters_per_gt_id": int(max_clusters_per_gt_id),
    }


def _to_int(x: Any, default: int = 0) -> int:
    """Best-effort int parsing for checklist validation.

    Accepts strings, floats, ints; returns default on failure.
    """

    try:
        if x is None:
            return int(default)
        if isinstance(x, bool):
            return int(x)
        return int(float(str(x)))
    except Exception:
        return int(default)



def _csv_has_any_nonempty_value(path: Path, *, column: str) -> bool:
    """Return True if *any* row has a non-empty value in the given column."""

    p = Path(path)
    with p.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or (column not in reader.fieldnames):
            return False
        for row in reader:
            v = row.get(column)
            if v is None:
                continue
            if str(v).strip() != "":
                return True
    return False


def _case_dirs(suite_dir: Path) -> List[Path]:
    cases_dir = Path(suite_dir) / "cases"
    if not cases_dir.exists() or not cases_dir.is_dir():
        return []
    out = [p for p in cases_dir.iterdir() if p.is_dir()]
    out.sort(key=lambda p: p.name)
    return out


def _discover_case_triage_queue_csv(case_dir: Path) -> Optional[Path]:
    """Best-effort locate triage_queue.csv for one case."""
    case_dir = Path(case_dir)
    preferred = case_dir / "analysis" / "_tables" / "triage_queue.csv"
    if preferred.exists():
        return preferred
    legacy = case_dir / "analysis" / "triage_queue.csv"
    if legacy.exists():
        return legacy
    return None


def _suite_plan_scanners(suite_dir: Path) -> List[str]:
    """Best-effort extract expected scanners from suite.json."""

    suite_json = Path(suite_dir) / "suite.json"
    if not suite_json.exists():
        return []
    try:
        raw = _read_json(suite_json)
    except Exception:
        return []
    if not isinstance(raw, dict):
        return []
    plan = raw.get("plan")
    if not isinstance(plan, dict):
        return []
    scanners = plan.get("scanners")
    if not isinstance(scanners, list):
        return []
    return sorted(set([str(x).strip() for x in scanners if str(x).strip()]))


def validate_calibration_suite_artifacts(
    suite_dir: str | Path,
    *,
    require_scored_queue: bool = True,
    expect_calibration: bool = True,
    expect_gt_tolerance_sweep: bool = False,
    expect_gt_tolerance_selection: bool = False,
) -> List[QACheck]:
    """Validate suite-level artifacts for the triage calibration workflow.

    Returns a list of checks. Use :func:`all_ok` to decide pass/fail.

    Parameters
    ----------
    suite_dir:
        Suite directory like runs/suites/<suite_id> (or a resolved LATEST).
    require_scored_queue:
        If True, require at least one non-empty triage_score_v1 in a per-case
        triage_queue.csv. This is the strongest filesystem signal that calibration
        weights were actually applied (i.e., you ran the *second analyze pass*).

        Set this to False only if you intentionally skipped re-analyzing cases.
    expect_calibration:
        If True, require calibration artifacts and that triage_eval includes the
        calibrated strategy. For non-scored suites (no GT / no calibration), set
        this to False to relax calibration-specific checks.
    """

    suite_dir = Path(suite_dir).resolve()
    out: List[QACheck] = []

    analysis_dir = suite_dir / "analysis"
    tables_dir = analysis_dir / "_tables"

    # --- Scanner config receipts (scientific reproducibility) ------------
    # In benchmarking, "tool output" depends on configuration (rules/profiles).
    # We require config receipts so suite-to-suite diffs can attribute drift to
    # configuration/profile changes.
    expected_scanners = _suite_plan_scanners(suite_dir)
    sc = summarize_scanner_config(suite_dir, scanners=expected_scanners)

    receipts_found = _to_int(sc.get("receipts_found"), 0)
    profile = sc.get("profile")
    profile_mode = str(sc.get("profile_mode") or "")
    missing_tools = sc.get("missing_tools") if isinstance(sc.get("missing_tools"), list) else []
    warnings_list = sc.get("warnings") if isinstance(sc.get("warnings"), list) else []

    ok_profile = bool(profile) and profile_mode != "unknown"
    ok_receipts = receipts_found > 0 and (len(missing_tools) == 0)
    warn_profile = profile_mode == "mixed"

    detail_parts: List[str] = []
    if not ok_receipts:
        if receipts_found <= 0:
            detail_parts.append("no config_receipt.json found under cases/*/tool_runs")
        if missing_tools:
            detail_parts.append(f"missing receipts for tools: {sorted(set([str(x) for x in missing_tools]))}")
    if warn_profile:
        detail_parts.append(f"profile drift inside suite: profile_mode={profile_mode}")
    if warnings_list:
        detail_parts.append("; ".join([str(w) for w in warnings_list if str(w).strip()]))

    out.append(
        QACheck(
            name="profile recorded + config receipts exist",
            ok=bool(ok_profile and ok_receipts),
            warn=bool(warn_profile or (warnings_list and ok_profile and ok_receipts)),
            path=str(suite_dir / "cases"),
            detail="; ".join([p for p in detail_parts if str(p).strip()]),
        )
    )

    # --- GT tolerance artifacts (optional, QA-driven) ----------------------
    # These are produced by the GT tolerance sweep/auto-selection flow.
    # They are only required when the caller explicitly expects them.

    sel_json = analysis_dir / "gt_tolerance_selection.json"
    selected_gt_tolerance: Optional[int] = None
    if expect_gt_tolerance_selection:
        out.append(
            QACheck(
                name="analysis/gt_tolerance_selection.json exists",
                ok=sel_json.exists(),
                path=str(sel_json),
                detail="" if sel_json.exists() else "missing",
            )
        )

        if sel_json.exists():
            try:
                payload = _read_json(sel_json)
            except Exception as e:  # pragma: no cover
                out.append(
                    QACheck(
                        name="analysis/gt_tolerance_selection.json parses",
                        ok=False,
                        path=str(sel_json),
                        detail=str(e),
                    )
                )
            else:
                sel_val = payload.get("selected_gt_tolerance") if isinstance(payload, dict) else None
                ok_val = False
                try:
                    int(sel_val)
                    ok_val = True
                except Exception:
                    ok_val = False

                if ok_val:
                    try:
                        selected_gt_tolerance = int(sel_val)  # type: ignore[arg-type]
                    except Exception:
                        selected_gt_tolerance = None

                out.append(
                    QACheck(
                        name="gt_tolerance_selection records selected_gt_tolerance",
                        ok=ok_val,
                        path=str(sel_json),
                        detail="" if ok_val else f"selected_gt_tolerance={sel_val!r}",
                    )
                )

                # Surface any selection warnings (non-fatal) directly in the checklist.
                # This is important for CI: ambiguous GT matching should be visible
                # without manually opening JSON artifacts.
                warnings_list: List[str] = []
                if isinstance(payload, dict):
                    # The writer nests the strategy output under selection{}.
                    sel_obj = payload.get("selection")
                    if isinstance(sel_obj, dict):
                        raw_warn = sel_obj.get("warnings")
                        if isinstance(raw_warn, list):
                            warnings_list = [str(w) for w in raw_warn if str(w).strip()]
                    # Backward compatibility: some older payloads may store warnings at the top level.
                    if not warnings_list:
                        raw_warn2 = payload.get("warnings")
                        if isinstance(raw_warn2, list):
                            warnings_list = [str(w) for w in raw_warn2 if str(w).strip()]

                out.append(
                    QACheck(
                        name="gt_tolerance_selection warnings",
                        ok=True,
                        warn=bool(warnings_list),
                        path=str(sel_json),
                        detail="; ".join(warnings_list) if warnings_list else "",
                    )
                )

    sweep_report = tables_dir / "gt_tolerance_sweep_report.csv"
    sweep_json = analysis_dir / "gt_tolerance_sweep.json"
    if expect_gt_tolerance_sweep:
        out.append(
            QACheck(
                name="analysis/_tables/gt_tolerance_sweep_report.csv exists",
                ok=sweep_report.exists(),
                path=str(sweep_report),
                detail="" if sweep_report.exists() else "missing",
            )
        )
        out.append(
            QACheck(
                name="analysis/gt_tolerance_sweep.json exists",
                ok=sweep_json.exists(),
                path=str(sweep_json),
                detail="" if sweep_json.exists() else "missing",
            )
        )


        # The sweep report is only trustworthy if the underlying per-case analyze
        # calls succeeded for each candidate tolerance. In QA mode, we treat any
        # non-zero analysis_rc in the sweep payload as a failure.
        if sweep_json.exists():
            try:
                payload = _read_json(sweep_json)
            except Exception as e:
                out.append(
                    QACheck(
                        name="analysis/gt_tolerance_sweep.json parses",
                        ok=False,
                        path=str(sweep_json),
                        detail=str(e),
                    )
                )
            else:
                rows = payload.get("rows") if isinstance(payload, dict) else None
                if not isinstance(rows, list):
                    out.append(
                        QACheck(
                            name="gt_tolerance_sweep has analysis_rc=0 for all candidates",
                            ok=False,
                            path=str(sweep_json),
                            detail="missing or invalid rows[] in sweep payload",
                        )
                    )
                else:
                    bad: List[str] = []
                    for r in rows:
                        if not isinstance(r, dict):
                            continue
                        t = _to_int(r.get("gt_tolerance"), 0)
                        rc = _to_int(r.get("analysis_rc"), 0)
                        if rc != 0:
                            bad.append(f"{t}:{rc}")

                    ok_rc = len(bad) == 0
                    out.append(
                        QACheck(
                            name="gt_tolerance_sweep has analysis_rc=0 for all candidates",
                            ok=ok_rc,
                            path=str(sweep_json),
                            detail="" if ok_rc else f"non-zero analysis_rc for tolerances: {', '.join(bad)}",
                        )
                    )

    # --- Expected suite-level artifacts ---------------------------------
    triage_dataset = tables_dir / "triage_dataset.csv"
    out.append(
        QACheck(
            name="analysis/_tables/triage_dataset.csv exists",
            ok=triage_dataset.exists(),
            path=str(triage_dataset),
            detail="" if triage_dataset.exists() else "missing",
        )
    )

    # --- GT ambiguity safety -------------------------------------------
    # High gt_tolerance values can create ambiguous GT matches:
    # - many-to-one: a single cluster overlaps multiple GT IDs
    # - one-to-many: a single GT ID overlaps multiple clusters
    # These are *warnings* (non-fatal) but should be visible in the checklist.
    if triage_dataset.exists():
        try:
            amb = _compute_gt_ambiguity_stats(triage_dataset)
        except Exception as e:  # pragma: no cover
            out.append(
                QACheck(
                    name="GT ambiguity stats computed",
                    ok=False,
                    path=str(triage_dataset),
                    detail=str(e),
                )
            )
        else:
            warn_amb = (int(amb.get("clusters_multi_gt", 0)) > 0) or (int(amb.get("gt_ids_multi_cluster", 0)) > 0)

            tol_suffix = f" (gt_tolerance={selected_gt_tolerance})" if selected_gt_tolerance is not None else ""
            detail = (
                f"many_to_one_clusters={int(amb.get('clusters_multi_gt', 0))}; "
                f"one_to_many_gt_ids={int(amb.get('gt_ids_multi_cluster', 0))}; "
                f"max_gt_ids_per_cluster={int(amb.get('max_gt_ids_per_cluster', 0))}; "
                f"max_clusters_per_gt_id={int(amb.get('max_clusters_per_gt_id', 0))}"
            )

            out.append(
                QACheck(
                    name=f"GT ambiguity warnings (many-to-one / one-to-many){tol_suffix}",
                    ok=True,
                    warn=bool(warn_amb),
                    path=str(triage_dataset),
                    detail=detail if warn_amb else "",
                )
            )

    triage_cal_json = analysis_dir / "triage_calibration.json"
    out.append(
        QACheck(
            name="analysis/triage_calibration.json exists",
            ok=(triage_cal_json.exists() if expect_calibration else True),
            path=str(triage_cal_json),
            detail=(
                ""
                if (triage_cal_json.exists() and expect_calibration)
                else ("missing" if expect_calibration else "skipped (non-scored mode)")
            ),
        )
    )

    if expect_calibration and triage_cal_json.exists():
        try:
            cal_data = json.loads(triage_cal_json.read_text(encoding="utf-8"))
        except Exception as e:
            out.append(
                QACheck(
                    name="analysis/triage_calibration.json parses",
                    ok=False,
                    path=str(triage_cal_json),
                    detail=str(e),
                )
            )
        else:
            included_cases = cal_data.get("included_cases")
            ok_inc = isinstance(included_cases, list) and len(included_cases) > 0
            out.append(
                QACheck(
                    name="triage_calibration includes >=1 GT-supported case",
                    ok=ok_inc,
                    path=str(triage_cal_json),
                    detail=(
                        ""
                        if ok_inc
                        else "included_cases is empty - suite may have no GT cases; calibration not meaningful"
                    ),
                )
            )

    triage_cal_report = tables_dir / "triage_calibration_report.csv"
    out.append(
        QACheck(
            name="analysis/_tables/triage_calibration_report.csv exists",
            ok=(triage_cal_report.exists() if expect_calibration else True),
            path=str(triage_cal_report),
            detail=(
                ""
                if (triage_cal_report.exists() and expect_calibration)
                else ("missing" if expect_calibration else "skipped (non-scored mode)")
            ),
        )
    )

    # --- triage_queue existence + schema check --------------------------
    # We validate across *all* cases in the suite (deterministic order)
    # so schema drift does not go unnoticed.
    queue_by_case: Dict[str, Path] = {}
    missing_queue_cases: List[str] = []
    for case_dir in _case_dirs(suite_dir):
        cid = case_dir.name
        p = _discover_case_triage_queue_csv(case_dir)
        if p is None:
            missing_queue_cases.append(cid)
        else:
            queue_by_case[cid] = p

    out.append(
        QACheck(
            name="per-case triage_queue.csv exists",
            ok=(len(missing_queue_cases) == 0 and len(queue_by_case) > 0),
            detail=(
                ""
                if (len(missing_queue_cases) == 0 and len(queue_by_case) > 0)
                else (
                    "no triage_queue.csv found" if not queue_by_case else f"missing for cases: {sorted(missing_queue_cases)}"
                )
            ),
            path=str(suite_dir / "cases"),
        )
    )

    # If no queues exist, we cannot validate schema.
    if queue_by_case:
        missing_col_cases: List[str] = []
        read_errors: List[str] = []
        for cid in sorted(queue_by_case.keys()):
            p = queue_by_case[cid]
            try:
                header = _read_csv_header(p)
                if "triage_score_v1" not in header:
                    missing_col_cases.append(cid)
            except Exception as e:
                read_errors.append(f"{cid}: {e}")

        ok_schema = (not missing_col_cases) and (not read_errors)
        detail_parts: List[str] = []
        if missing_col_cases:
            detail_parts.append(f"missing triage_score_v1 for cases: {sorted(missing_col_cases)}")
        if read_errors:
            detail_parts.append(f"CSV read errors: {read_errors}")

        out.append(
            QACheck(
                name="triage_queue.csv contains column triage_score_v1",
                ok=ok_schema,
                detail="; ".join(detail_parts),
                path=str(suite_dir / "cases"),
            )
        )

        # End-to-end signal: at least one triage_queue row should have a scored value
        # once calibration has been built and the suite re-analyzed.
        if require_scored_queue:
            any_scored = False
            for cid in sorted(queue_by_case.keys()):
                p = queue_by_case[cid]
                try:
                    if _csv_has_any_nonempty_value(p, column="triage_score_v1"):
                        any_scored = True
                        break
                except Exception:
                    continue

            out.append(
                QACheck(
                    name="triage_queue.csv has non-empty triage_score_v1",
                    ok=bool(any_scored),
                    detail="" if any_scored else "all triage_score_v1 values are empty (calibration likely not applied)",
                    path=str(suite_dir / "cases"),
                )
            )
        else:
            out.append(
                QACheck(
                    name="triage_queue.csv has non-empty triage_score_v1",
                    ok=True,
                    detail="skipped (no reanalyze)",
                    path=str(suite_dir / "cases"),
                )
            )
    else:
        # Preserve the legacy check name for compatibility with downstream tooling.
        out.append(
            QACheck(
                name="triage_queue.csv contains column triage_score_v1",
                ok=False,
                detail="no triage_queue.csv found under cases/*/analysis (analysis may have been skipped)",
                path=str(suite_dir / "cases"),
            )
        )

    # --- triage_eval strategy check -------------------------------------
    eval_summary = tables_dir / "triage_eval_summary.json"

    # Tool contribution / marginal value outputs are emitted by suite_triage_eval.
    # They help answer two pragmatic questions:
    #  - "Which tools cover unique GT?" (triage_tool_utility.csv)
    #  - "What happens if we remove tool X?" (triage_tool_marginal.csv)
    tool_utility_csv = tables_dir / "triage_tool_utility.csv"
    tool_marginal_csv = tables_dir / "triage_tool_marginal.csv"

    if not expect_calibration:
        out.append(
            QACheck(
                name="triage_eval_summary includes strategy calibrated",
                ok=True,
                detail="skipped (non-scored mode)",
                path=str(eval_summary),
            )
        )

        out.append(
            QACheck(
                name="triage_eval_summary includes strategy calibrated_global",
                ok=True,
                detail="skipped (non-scored mode)",
                path=str(eval_summary),
            )
        )

        # These are only meaningful for scored suites. Keep the checklist
        # stable by explicitly marking them as skipped in non-scored mode.
        out.append(
            QACheck(
                name="analysis/_tables/triage_tool_utility.csv exists",
                ok=True,
                detail="skipped (non-scored mode)",
                path=str(tool_utility_csv),
            )
        )
        out.append(
            QACheck(
                name="analysis/_tables/triage_tool_marginal.csv exists",
                ok=True,
                detail="skipped (non-scored mode)",
                path=str(tool_marginal_csv),
            )
        )
        return out

    # In scored/calibrated runs, these two files are expected outputs.
    # If they are missing, it usually means suite_triage_eval did not run
    # or wrote to an unexpected location.
    out.append(
        QACheck(
            name="analysis/_tables/triage_tool_utility.csv exists",
            ok=tool_utility_csv.exists(),
            path=str(tool_utility_csv),
            detail="" if tool_utility_csv.exists() else "missing",
        )
    )
    out.append(
        QACheck(
            name="analysis/_tables/triage_tool_marginal.csv exists",
            ok=tool_marginal_csv.exists(),
            path=str(tool_marginal_csv),
            detail="" if tool_marginal_csv.exists() else "missing",
        )
    )

    if not eval_summary.exists():
        out.append(
            QACheck(
                name="triage_eval_summary includes strategy calibrated_global",
                ok=False,
                detail="missing triage_eval_summary.json",
                path=str(eval_summary),
            )
        )
        out.append(
            QACheck(
                name="triage_eval_summary includes strategy calibrated",
                ok=False,
                detail="missing triage_eval_summary.json",
                path=str(eval_summary),
            )
        )
    else:
        try:
            payload = _read_json(eval_summary)
            strategies = payload.get("strategies") if isinstance(payload, dict) else None
            strategies_list = list(strategies) if isinstance(strategies, list) else []
            ok_calibrated = "calibrated" in strategies_list
            ok_global = "calibrated_global" in strategies_list
            detail_calibrated = "" if ok_calibrated else f"strategies={strategies_list}"
            detail_global = "" if ok_global else f"strategies={strategies_list}"
            out.append(
                QACheck(
                    name="triage_eval_summary includes strategy calibrated",
                    ok=ok_calibrated,
                    detail=detail_calibrated,
                    path=str(eval_summary),
                )
            )
            out.append(
                QACheck(
                    name="triage_eval_summary includes strategy calibrated_global",
                    ok=ok_global,
                    detail=detail_global,
                    path=str(eval_summary),
                )
            )
        except Exception as e:
            out.append(
                QACheck(
                    name="triage_eval_summary includes strategy calibrated",
                    ok=False,
                    detail=f"failed to read/parse JSON: {e}",
                    path=str(eval_summary),
                )
            )

            out.append(
                QACheck(
                    name="triage_eval_summary includes strategy calibrated_global",
                    ok=False,
                    detail=f"failed to read/parse JSON: {e}",
                    path=str(eval_summary),
                )
            )

    return out
