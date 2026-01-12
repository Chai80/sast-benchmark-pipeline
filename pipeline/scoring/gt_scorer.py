from __future__ import annotations

"""pipeline.scoring.gt_scorer

Ground-truth scoring helpers (minimal).

This repo's primary goal is *benchmarking tool output*. True GT scoring is a
separate concern and often requires:
- a GT schema
- mapping rules/categories between tools
- human adjudication

For now, this module provides a small, location-based scorer that can be used
incrementally.

GT file format (v0)
-------------------
A JSON array of objects, each containing:
- file_path: str
- line_number: int | null

Example:
[
  {"file_path": "src/app/foo.py", "line_number": 42},
  {"file_path": "src/app/bar.py", "line_number": 10}
]

Scoring
-------
We treat a prediction as correct if it matches a GT location key exactly.
For tolerance-based scoring, add clustering upstream (future work).

"""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from pipeline.analysis.utils.path_norm import normalize_file_path


def _loc_key(file_path: str, line_number: Optional[int], *, repo_name: Optional[str] = None) -> str:
    fp = normalize_file_path(file_path or "", repo_name=repo_name)
    ln = int(line_number) if line_number is not None else 0
    return f"{fp}:{ln}"


def score_locations(
    *,
    predicted: Iterable[Tuple[str, Optional[int]]],
    ground_truth: Iterable[Tuple[str, Optional[int]]],
    repo_name: Optional[str] = None,
) -> Dict[str, Any]:
    p_set = {_loc_key(fp, ln, repo_name=repo_name) for fp, ln in predicted}
    gt_set = {_loc_key(fp, ln, repo_name=repo_name) for fp, ln in ground_truth}

    tp = len(p_set & gt_set)
    fp = len(p_set - gt_set)
    fn = len(gt_set - p_set)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "predicted": len(p_set),
        "ground_truth": len(gt_set),
    }


def score_from_files(
    *,
    normalized_json: Path,
    gt_json: Path,
    repo_name: Optional[str] = None,
) -> Dict[str, Any]:
    norm = json.loads(Path(normalized_json).read_text(encoding="utf-8"))
    findings = norm.get("findings") or []
    predicted = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        predicted.append((str(f.get("file_path") or ""), f.get("line_number")))

    gt = json.loads(Path(gt_json).read_text(encoding="utf-8"))
    ground_truth = []
    if isinstance(gt, list):
        for row in gt:
            if isinstance(row, dict):
                ground_truth.append((str(row.get("file_path") or ""), row.get("line_number")))

    return score_locations(predicted=predicted, ground_truth=ground_truth, repo_name=repo_name)


def main(argv: List[str] | None = None) -> None:  # pragma: no cover
    """CLI entrypoint for quick GT scoring experiments.

    This is intentionally small and filesystem-first: it reads a tool's
    normalized.json output and a simple GT JSON catalog, then prints a score
    report (or writes it to --out).
    """
    ap = argparse.ArgumentParser(
        description="Score normalized findings against a GT JSON catalog (location-based)."
    )
    ap.add_argument("normalized_json", help="Path to normalized.json produced by a tool run")
    ap.add_argument("gt_json", help="Path to GT JSON catalog (list of {file_path,line_number})")
    ap.add_argument("--repo-name", help="Optional repo name used for file-path normalization")
    ap.add_argument("--out", help="Optional output JSON path. If omitted, prints to stdout.")
    args = ap.parse_args(argv)

    norm_p = Path(args.normalized_json).expanduser()
    gt_p = Path(args.gt_json).expanduser()
    if not norm_p.exists():
        raise SystemExit(f"normalized.json not found: {norm_p}")
    if not gt_p.exists():
        raise SystemExit(f"GT catalog not found: {gt_p}")

    result = score_from_files(normalized_json=norm_p, gt_json=gt_p, repo_name=args.repo_name)
    out = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        out_path = Path(args.out).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out + "\n", encoding="utf-8")
    else:
        print(out)


if __name__ == "__main__":  # pragma: no cover
    main()
