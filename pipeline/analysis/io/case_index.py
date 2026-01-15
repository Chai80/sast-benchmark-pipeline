from __future__ import annotations

"""pipeline.analysis.io.case_index

Suite-level analysis index helpers.

As soon as you start building a calibration / data-science layer (triage
training sets, learned weights, eval reports), you need a reliable way to
answer:

- Which cases in a suite were analyzed?
- Which expected per-case artifacts exist (triage tables, manifests, packs)?

Rather than having each downstream script re-implement filesystem globbing and
layout heuristics, we write a small, suite-level index:

  runs/suites/<suite_id>/analysis/case_index.json

This file is filesystem-first and best-effort.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence

from tools.io import write_json


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _exists(p: Path) -> bool:
    try:
        return Path(p).exists()
    except Exception:
        return False


def _exists_any(paths: Sequence[Path]) -> bool:
    for p in paths:
        if _exists(p):
            return True
    return False


def build_case_index(*, suite_dir: Path, case_ids: Sequence[str]) -> Dict[str, Any]:
    """Build the JSON-serializable payload for case_index.json."""

    suite_dir = Path(suite_dir).resolve()
    cases_dir = suite_dir / "cases"

    rows: List[Dict[str, Any]] = []
    for cid in case_ids:
        case_dir = (cases_dir / str(cid)).resolve()
        analysis_dir = case_dir / "analysis"
        tables_dir = analysis_dir / "_tables"
        gt_dir = case_dir / "gt"

        exists_map = {
            # Top-level dirs
            "case_dir": _exists(case_dir),
            "analysis_dir": _exists(analysis_dir),
            "tool_runs_dir": _exists(case_dir / "tool_runs"),
            "scans_dir": _exists(case_dir / "scans"),
            "gt_dir": _exists(gt_dir),

            # Common analysis artifacts
            "analysis_manifest_json": _exists(analysis_dir / "analysis_manifest.json"),
            "benchmark_pack_json": _exists(analysis_dir / "benchmark_pack.json"),
            "hotspot_drilldown_pack_json": _exists(analysis_dir / "hotspot_drilldown_pack.json"),

            # Tables (triage)
            "triage_features_csv": _exists_any(
                [tables_dir / "triage_features.csv", analysis_dir / "triage_features.csv"]
            ),
            "triage_queue_csv": _exists_any(
                [tables_dir / "triage_queue.csv", analysis_dir / "triage_queue.csv"]
            ),

            # GT artifacts
            "gt_catalog_yaml": _exists_any([gt_dir / "gt_catalog.yaml", gt_dir / "gt_catalog.yml"]),
            "gt_score_json": _exists(gt_dir / "gt_score.json"),
            "gt_score_csv": _exists(gt_dir / "gt_score.csv"),
        }

        rows.append(
            {
                "case_id": str(cid),
                "case_dir": str(case_dir),
                "analysis_dir": str(analysis_dir),
                "exists": exists_map,
            }
        )

    return {
        "generated_at": _now_iso(),
        "suite_id": suite_dir.name,
        "suite_dir": str(suite_dir),
        "cases": rows,
    }


def _yesno(v: object) -> str:
    return "YES" if bool(v) else "NO"


def _render_suite_readme(payload: dict, *, index_path: Path) -> str:
    """
    Human-friendly landing page for a suite analysis folder.

    Written to:
      runs/suites/<suite_id>/analysis/README.txt
    """
    suite_id = str(payload.get("suite_id") or "")
    suite_dir = str(payload.get("suite_dir") or "")
    generated_at = str(payload.get("generated_at") or "")

    lines: list[str] = []
    lines.append("Suite analysis outputs")
    lines.append("======================")
    lines.append(f"Suite ID   : {suite_id}")
    lines.append(f"Generated  : {generated_at}")
    lines.append(f"Suite dir  : {suite_dir}")
    lines.append("")
    lines.append("Where is the analysis?")
    lines.append("----------------------")
    lines.append("Per-case analysis outputs live under:")
    lines.append(f"  runs/suites/{suite_id}/cases/<case_id>/analysis/")
    lines.append("")
    lines.append("CSV tables are typically under each case's:")
    lines.append("  analysis/_tables/")
    lines.append("")
    lines.append("Suite-level outputs (this folder) live under:")
    lines.append(f"  runs/suites/{suite_id}/analysis/")
    lines.append("")
    lines.append("Index files")
    lines.append("-----------")
    lines.append(f"- case_index.json : {index_path.name}")
    lines.append("- README.txt      : README.txt")
    lines.append("")
    lines.append("Case summary (selected existence flags)")
    lines.append("--------------------------------------")

    cases = payload.get("cases") or []
    if isinstance(cases, list):
        for c in cases:
            if not isinstance(c, dict):
                continue
            cid = str(c.get("case_id") or "")
            exists = c.get("exists") or {}
            if not isinstance(exists, dict):
                exists = {}

            triage_features = _yesno(exists.get("triage_features_csv"))
            triage_queue = _yesno(exists.get("triage_queue_csv"))
            manifest = _yesno(exists.get("analysis_manifest_json"))
            gt_catalog = _yesno(exists.get("gt_catalog_yaml"))
            gt_score = _yesno(bool(exists.get("gt_score_json")) or bool(exists.get("gt_score_csv")))

            lines.append(
                f"- {cid}: triage_features={triage_features} triage_queue={triage_queue} "
                f"manifest={manifest} gt_catalog={gt_catalog} gt_score={gt_score}"
            )

    lines.append("")
    lines.append("Tip")
    lines.append("---")
    lines.append("Open one case's triage queue:")
    lines.append("  head -n 5 runs/suites/<suite_id>/cases/<case_id>/analysis/_tables/triage_queue.csv")
    lines.append("")
    return "\n".join(lines) + "\n"


def write_case_index_json(suite_dir: Path, *, case_ids: Sequence[str]) -> Path:
    """Write <suite_dir>/analysis/case_index.json and return its path."""

    suite_dir = Path(suite_dir).resolve()
    out_dir = suite_dir / "analysis"
    out_dir.mkdir(parents=True, exist_ok=True)

    out_path = out_dir / "case_index.json"
    payload = build_case_index(suite_dir=suite_dir, case_ids=case_ids)
    write_json(out_path, payload)
    readme_path = out_dir / "README.txt"
    readme_path.write_text(_render_suite_readme(payload, index_path=out_path), encoding="utf-8")

    return out_path
