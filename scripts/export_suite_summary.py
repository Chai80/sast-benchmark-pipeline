from __future__ import annotations

"""Export a suite-level summary CSV from per-case benchmark_pack.json artifacts.

This is a lightweight helper for quickly building a scoreboard across cases
without changing run directory structure.

Example:
  python scripts/export_suite_summary.py \
    --suite-dir runs/suites/20260113T195719Z \
    --out /tmp/suite_summary.csv
"""

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

# Allow running this script directly (python scripts/export_suite_summary.py)
# without requiring PYTHONPATH=.
if __package__ in (None, ""):
    _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)

from pipeline.analysis.utils.owasp import infer_owasp


def _read_json(p: Path) -> Dict[str, Any]:
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _extract_tool_profile(pack: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for row in pack.get("tool_profile") or []:
        if not isinstance(row, dict):
            continue
        tool = str(row.get("tool") or "").strip()
        if not tool:
            continue
        out[f"{tool}_findings"] = row.get("findings", 0)
        out[f"{tool}_high"] = row.get("high", 0)
        out[f"{tool}_medium"] = row.get("medium", 0)
        out[f"{tool}_low"] = row.get("low", 0)
    return out


def collect_suite_rows(suite_dir: Path) -> List[Dict[str, Any]]:
    cases_dir = suite_dir / "cases"
    if not cases_dir.exists() or not cases_dir.is_dir():
        raise SystemExit(f"Invalid suite dir (missing cases/): {suite_dir}")

    rows: List[Dict[str, Any]] = []
    for case_dir in sorted([p for p in cases_dir.iterdir() if p.is_dir()]):
        pack_path = case_dir / "analysis" / "benchmark_pack.json"
        if not pack_path.exists():
            continue
        pack = _read_json(pack_path)

        ctx = pack.get("context") or {}
        suite_id = ctx.get("suite_id") or suite_dir.name
        case_id = ctx.get("case_id") or case_dir.name
        tools = ctx.get("tools") or []

        # Use pack-provided OWASP if present, otherwise infer.
        owasp_id = ctx.get("owasp_id")
        owasp_title = ctx.get("owasp_title")
        if not owasp_id:
            owasp_id, owasp_title = infer_owasp(
                str(case_id), out_dir=case_dir / "analysis"
            )

        summary = pack.get("summary") or {}
        row: Dict[str, Any] = {
            "suite_id": suite_id,
            "case_id": case_id,
            "owasp_id": owasp_id or "",
            "owasp_title": owasp_title or "",
            "tools": ",".join([str(t) for t in tools]),
            "triage_items": summary.get("triage_items", 0),
            "top_agreement": summary.get("top_agreement", 0),
            "tolerance": ctx.get("tolerance"),
            "gt_tolerance": ctx.get("gt_tolerance"),
            "exclude_prefixes": ",".join(ctx.get("exclude_prefixes") or []),
            "include_harness": bool(ctx.get("include_harness", False)),
        }
        row.update(_extract_tool_profile(pack))
        rows.append(row)

    return rows


def write_rows_csv(rows: List[Dict[str, Any]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames: List[str] = []
    # stable leading columns
    base = [
        "suite_id",
        "case_id",
        "owasp_id",
        "owasp_title",
        "tools",
        "triage_items",
        "top_agreement",
        "tolerance",
        "gt_tolerance",
        "exclude_prefixes",
        "include_harness",
    ]
    fieldnames.extend(base)

    # include any per-tool columns discovered
    extra = sorted({k for r in rows for k in r.keys() if k not in fieldnames})
    fieldnames.extend(extra)

    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


def main(argv: List[str] | None = None) -> None:
    ap = argparse.ArgumentParser(
        description="Export suite summary CSV from benchmark_pack.json"
    )
    ap.add_argument("--suite-dir", required=True, help="Path to runs/suites/<suite_id>")
    ap.add_argument("--out", required=True, help="Output CSV path")
    args = ap.parse_args(argv)

    suite_dir = Path(args.suite_dir)
    rows = collect_suite_rows(suite_dir)
    if not rows:
        raise SystemExit(f"No benchmark_pack.json found under: {suite_dir}")

    out_path = Path(args.out)
    write_rows_csv(rows, out_path)
    print(f"Wrote {len(rows)} rows -> {out_path}")


if __name__ == "__main__":
    main()
