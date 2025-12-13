# benchmarks/runtime.py
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from benchmarks.targets import BENCHMARKS
from pipeline.core import build_command

ROOT_DIR = Path(__file__).resolve().parents[1]


def run_and_time(cmd: List[str]) -> Tuple[int, float]:
    """
    Run a command as a subprocess and measure wall-clock runtime.

    Returns (exit_code, elapsed_seconds).
    """
    start = time.perf_counter()
    result = subprocess.run(cmd)
    elapsed = time.perf_counter() - start
    return result.returncode, elapsed


def _repo_name_for_target(target_key: str) -> str:
    """
    Derive the repo folder name for a given benchmark target.

    Mirrors tools/run_utils.py get_repo_name behavior.
    """
    entry = BENCHMARKS.get(target_key)
    if not entry:
        raise ValueError(f"Unknown target '{target_key}' in BENCHMARKS")

    repo_url = entry.get("repo_url")
    if not repo_url:
        raise ValueError(f"No repo_url configured for target '{target_key}'")

    last = repo_url.rstrip("/").split("/")[-1]
    return last[:-4] if last.endswith(".git") else last


def get_latest_run_dir(scanner: str, target_key: str) -> Path | None:
    """
    Find the latest run directory for a given scanner + target.

    Preferred layout (new):
        runs/<scanner>/<repo_name>/<run_id>/

    Backward-compatible fallback (old):
        runs/<scanner>/<run_id>/

    We assume run_id folders are YYYYMMDDNN and lexicographically sortable.
    """
    roots_to_try: List[Path] = []

    # Try structured layout first
    try:
        repo_name = _repo_name_for_target(target_key)
        roots_to_try.append(ROOT_DIR / "runs" / scanner / repo_name)
    except Exception:
        pass

    # Fallback to flat layout
    roots_to_try.append(ROOT_DIR / "runs" / scanner)

    for root in roots_to_try:
        if not root.exists():
            continue

        candidates = [p for p in root.iterdir() if p.is_dir()]
        if not candidates:
            continue

        latest = max(candidates, key=lambda p: p.name)
        return latest

    return None


def read_metadata_from_run(scanner: str, target_key: str) -> Dict[str, Any]:
    """
    Load metadata.json from the latest run directory for the given scanner+target.

    Returns {} if we can't find it.
    """
    run_dir = get_latest_run_dir(scanner, target_key)
    if run_dir is None:
        return {}

    meta_path = run_dir / "metadata.json"
    if not meta_path.exists():
        return {}

    try:
        with meta_path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def run_sast_runtime_benchmark(
    target_key: str,
    scanners: List[str],
) -> Dict[str, Any]:
    """
    Run each scanner for the given target and collect runtime metrics.

    Notes:
    - wall_clock_seconds is measured here around the full scanner command.
    - scan_time_seconds is read from each tool's metadata.json.
    """
    if target_key not in BENCHMARKS:
        raise ValueError(
            f"Unknown target '{target_key}'. "
            f"Valid options: {', '.join(sorted(BENCHMARKS.keys()))}"
        )

    summary_results: List[Dict[str, Any]] = []

    for scanner in scanners:
        print(f"\n▶️  Benchmarking scanner: {scanner} on target: {target_key}")

        # Build the command using core logic (NOT the CLI)
        try:
            cmd = build_command(scanner, target_key)
        except Exception as e:
            print(f"  ⚠️ Failed to build command for {scanner}: {e}")
            summary_results.append(
                {
                    "scanner": scanner,
                    "exit_code": None,
                    "wall_clock_seconds": None,
                    "run_id": None,
                    "scan_time_seconds": None,
                    "error": f"build_command failed: {e}",
                }
            )
            continue

        print("  Command:", " ".join(cmd))
        exit_code, wall_seconds = run_and_time(cmd)
        print(f"  Finished with exit_code={exit_code}, wall_clock={wall_seconds:.2f}s")

        meta = read_metadata_from_run(scanner, target_key)
        run_id = meta.get("run_id")
        scan_time_seconds = meta.get("scan_time_seconds")

        if not meta:
            print("  ⚠️ Could not locate metadata.json for this run.")

        summary_results.append(
            {
                "scanner": scanner,
                "exit_code": exit_code,
                "wall_clock_seconds": wall_seconds,
                "run_id": run_id,
                "scan_time_seconds": scan_time_seconds,
            }
        )

    return {
        "benchmark_target": target_key,
        "timestamp": datetime.now().isoformat(),
        "results": summary_results,
    }


def print_summary_table(summary: Dict[str, Any]) -> None:
    """
    Pretty-print a small table of benchmark results to stdout.
    """
    target = summary.get("benchmark_target")
    print(f"\nRuntime benchmark for {target}")
    print("-" * (24 + len(str(target))))

    for row in summary.get("results", []):
        scanner = row.get("scanner")
        wall = row.get("wall_clock_seconds")
        run_id = row.get("run_id")

        if wall is None:
            line = f"{scanner:<8}:   n/a  (no run)"
        else:
            line = f"{scanner:<8}: {wall:6.2f} s"
            if run_id:
                line += f" (run_id {run_id})"
        print(line)


def save_benchmark_summary(
    summary: Dict[str, Any],
    output_root: Path | None = None,
) -> Path:
    """
    Save the benchmark summary as JSON under runs/benchmarks/.

    Returns the path to the saved file.
    """
    if output_root is None:
        output_root = ROOT_DIR / "runs" / "benchmarks"
    elif not output_root.is_absolute():
        output_root = ROOT_DIR / output_root

    output_root.mkdir(parents=True, exist_ok=True)

    target = summary.get("benchmark_target", "unknown_target")
    timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    out_path = output_root / f"{timestamp}_{target}_runtime.json"

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    return out_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark runtime of SAST scanners for a given target."
    )
    parser.add_argument(
        "--target",
        required=True,
        help=f"Logical benchmark target (one of: {', '.join(sorted(BENCHMARKS.keys()))})",
    )
    parser.add_argument(
        "--scanners",
        default="semgrep,snyk,sonar,aikido",
        help="Comma-separated list of scanners to benchmark "
             "(default: semgrep,snyk,sonar,aikido)",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not write benchmark summary JSON to runs/benchmarks/.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    scanners = [s.strip() for s in args.scanners.split(",") if s.strip()]
    if not scanners:
        print("ERROR: No scanners specified.", file=sys.stderr)
        sys.exit(1)

    summary = run_sast_runtime_benchmark(args.target, scanners)
    print_summary_table(summary)

    if not args.no_save:
        out_path = save_benchmark_summary(summary)
        print(f"\n📄 Benchmark summary saved to: {out_path}")


if __name__ == "__main__":
    main()
