"""pipeline.analysis.analyze_suite

Run the full analysis suite for a repo from existing normalized runs.

This is the "one command" that turns raw scans into comparative benchmark artifacts.

Pipeline (filesystem only)
--------------------------
1) unique_overview      -> latest_hotspots_by_file.json
2) hotspot_matrix       -> coarse overlap matrix (file|OWASP)
3) hotspot_location_matrix (clustered) -> granular overlap matrix (file|Lstart-end)
4) taxonomy_analysis    -> taxonomy disagreement classification (on overlaps)
5) tool_profile         -> output quality & metadata completeness per tool
6) pairwise_agreement   -> similarity + incremental coverage between tools
7) triage_queue         -> prioritized rows for manual adjudication
8) benchmark_pack       -> single JSON summary you can share

All outputs are written under:
  runs/analysis/<repo_name>/

No DB, no dashboards.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Sequence

from pipeline.analysis.io_utils import write_json
from pipeline.analysis.meta_utils import with_standard_meta

from pipeline.analysis.unique_overview import analyze_latest_hotspots_for_repo
from pipeline.analysis.hotspot_matrix import build_hotspot_matrix, write_matrix_outputs as write_hotspot_matrix
from pipeline.analysis.hotspot_location_matrix import build_hotspot_location_matrix, write_matrix_outputs as write_location_matrix
from pipeline.analysis.taxonomy_analysis import build_taxonomy_report, write_outputs as write_taxonomy
from pipeline.analysis.tool_profile import build_tool_profile, write_outputs as write_tool_profile
from pipeline.analysis.pairwise_agreement import build_pairwise_agreement, write_outputs as write_pairwise
from pipeline.analysis.triage_queue import build_triage_queue, write_outputs as write_triage
from pipeline.analysis.benchmark_pack import build_benchmark_pack, write_outputs as write_benchmark_pack


def _parse_tools_csv(raw: str | None) -> List[str]:
    if not raw:
        return []
    items = [t.strip() for t in raw.split(",")]
    return [t for t in items if t]


def run_suite(
    *,
    repo_name: str,
    tools: Sequence[str],
    runs_dir: Path,
    out_dir: Path,
    tolerance: int = 3,
    mode: str = "security",
    formats: Sequence[str] = ("json", "csv"),
) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1) unique_overview report
    report = analyze_latest_hotspots_for_repo(repo_name, tools=tools, runs_dir=runs_dir)
    # Standardize metadata for this top-level artifact (without changing its existing keys)
    if isinstance(report, dict):
        report_meta = report.get("meta") if isinstance(report.get("meta"), dict) else {}
        report["meta"] = with_standard_meta(
            report_meta,
            stage="unique_overview",
            repo=repo_name,
            tool_names=list(tools),
        )
    report_path = out_dir / "latest_hotspots_by_file.json"
    write_json(report, report_path)

    # 2) coarse hotspot matrix (file|OWASP)
    coarse = build_hotspot_matrix(report_path)
    write_hotspot_matrix(coarse, out_dir, "latest_hotspot_matrix", list(formats))

    # 3) clustered location matrix (file|Lstart-end) union (min_tools=1)
    loc_matrix = build_hotspot_location_matrix(
        report_path,
        tolerance=tolerance,
        mode=mode,
        min_tools=1,
    )
    write_location_matrix(loc_matrix, out_dir, "latest_hotspot_location_matrix", list(formats))
    loc_matrix_path = out_dir / "latest_hotspot_location_matrix.json"

    # 4) taxonomy analysis on overlaps (min_tools=2)
    tax = build_taxonomy_report(loc_matrix_path, min_tools=2)
    write_taxonomy(tax, out_dir, "taxonomy_analysis", list(formats))
    tax_path = out_dir / "taxonomy_analysis.json"

    # 5) tool profile
    tp = build_tool_profile(matrix_path=loc_matrix_path, report_path=None, mode=mode)
    write_tool_profile(tp, out_dir, "tool_profile", list(formats))

    # 6) pairwise agreement
    pa = build_pairwise_agreement(loc_matrix_path)
    write_pairwise(pa, out_dir, "pairwise_agreement", list(formats))

    # 7) triage queue
    tq = build_triage_queue(loc_matrix_path, tax_path, limit=200)
    write_triage(tq, out_dir, "triage_queue", list(formats))

    # 8) benchmark pack
    pack = build_benchmark_pack(matrix_path=loc_matrix_path, taxonomy_path=tax_path, mode_for_profiles=mode, max_examples=10)
    write_benchmark_pack(pack, out_dir, "benchmark_pack", list(formats))

    summary = {
        "repo": repo_name,
        "tools": list(tools),
        "runs_dir": str(runs_dir),
        "out_dir": str(out_dir),
        "artifacts": {
            "unique_overview": str(report_path),
            "hotspot_matrix": str(out_dir / "latest_hotspot_matrix.json"),
            "hotspot_location_matrix": str(loc_matrix_path),
            "taxonomy_analysis": str(tax_path),
            "tool_profile": str(out_dir / "tool_profile.json"),
            "pairwise_agreement": str(out_dir / "pairwise_agreement.json"),
            "triage_queue": str(out_dir / "triage_queue.csv"),
            "benchmark_pack": str(out_dir / "benchmark_pack.json"),
        },
    }

    # 9) suite manifest (single pointer file for everything we produced)
    manifest_path = out_dir / "suite_manifest.json"
    manifest = dict(summary)
    manifest["meta"] = with_standard_meta(
        {},
        stage="analysis_suite",
        repo=repo_name,
        tool_names=list(tools),
        mode=mode,
        tolerance=int(tolerance),
    )
    write_json(manifest, manifest_path)
    summary.setdefault("artifacts", {})["suite_manifest"] = str(manifest_path)

    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the full analysis suite (filesystem artifacts only).")
    ap.add_argument("--repo-name", required=True, help="Repo name as used under runs/<tool>/<repo_name>/...")
    ap.add_argument("--runs-dir", default=str(Path(__file__).resolve().parents[2] / "runs"), help="Base runs directory (default: <repo_root>/runs)")
    ap.add_argument("--out-dir", help="Output directory (default: runs/analysis/<repo-name>/)")
    ap.add_argument("--tools", help="Comma-separated tools (default: semgrep,snyk,sonar,aikido)")
    ap.add_argument("--tolerance", type=int, default=3, help="Line clustering tolerance (default: 3)")
    ap.add_argument("--mode", choices=["security", "all"], default="security", help="Filtering mode (default: security)")
    ap.add_argument("--formats", default="json,csv", help="Comma-separated formats to write (json,csv)")

    args = ap.parse_args()
    tools = _parse_tools_csv(args.tools) or ["semgrep", "snyk", "sonar", "aikido"]
    runs_dir = Path(args.runs_dir)
    out_dir = Path(args.out_dir) if args.out_dir else (runs_dir / "analysis" / args.repo_name)
    formats = [f.strip() for f in str(args.formats).split(",") if f.strip()]

    summary = run_suite(
        repo_name=args.repo_name,
        tools=tools,
        runs_dir=runs_dir,
        out_dir=out_dir,
        tolerance=int(args.tolerance),
        mode=args.mode,
        formats=formats,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
