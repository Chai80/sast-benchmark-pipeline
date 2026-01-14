from __future__ import annotations

from pathlib import Path
from typing import Optional

from cli.common import parse_csv
from pipeline.models import CaseSpec
from pipeline.orchestrator import AnalyzeRequest
from pipeline.pipeline import SASTBenchmarkPipeline
from pipeline.scanners import DEFAULT_SCANNERS_CSV, SUPPORTED_SCANNERS


def run_analyze(
    args,
    pipeline: SASTBenchmarkPipeline,
    *,
    case: CaseSpec,
    suite_root: Path,
    suite_id: Optional[str],
) -> int:
    metric = args.metric or "hotspots"

    tools_csv = args.tools or DEFAULT_SCANNERS_CSV
    tools = [t for t in parse_csv(tools_csv) if t in SUPPORTED_SCANNERS]

    req = AnalyzeRequest(
        metric=metric,
        case=case,
        suite_root=suite_root,
        suite_id=suite_id,
        case_path=args.case_path,
        runs_dir=Path(args.runs_dir) if args.runs_dir else None,
        tools=tools,
        output_format=str(args.format),
        out=args.out,
        analysis_out_dir=args.analysis_out_dir,
        tolerance=int(args.tolerance),
        gt_tolerance=int(getattr(args, "gt_tolerance", 0)),
        analysis_filter=str(args.analysis_filter),
        exclude_prefixes=getattr(args, "exclude_prefixes", ()) or (),
        include_harness=bool(getattr(args, "include_harness", False)),
        max_unique=int(args.max_unique),
    )
    return int(pipeline.analyze(req))
