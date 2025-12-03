import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

# One-way dependency: this module imports from sast_cli.
# sast_cli SHOULD NOT import benchmarks.runtime at module import time.
from sast_cli import BENCHMARKS, build_command  # type: ignore[attr-defined]


def run_and_time(cmd: List[str]) -> Tuple[int, float]:
    """
    Run a command as a subprocess and measure wall-clock runtime.

    Returns (exit_code, elapsed_seconds).
    """
    start = time.perf_counter()
    result = subprocess.run(cmd)
    elapsed = time.perf_counter() - start
    return result.returncode, elapsed


def get_latest_run_dir(scanner: str) -> Path | None:
    """
    Find the latest run directory for a given scanner, e.g.:

        runs/semgrep/2025120101
        runs/snyk/2025120103

    We assume run directory names are YYYYMMDDNN and lexicographically sortable.
    """
    root = Path("runs") / scanner
    if not root.exists():
        return None

    candidates = [p for p in root.iterdir() if p.is_dir()]
    if not candidates:
        return None

    # Lexicographically largest YYYYMMDDNN is "latest"
    latest = max(candidates, key=lambda p: p.name)
    return latest


def read_metadata_from_run(scanner: str) -> Dict[str, Any]:
    """
    Load metadata.json from the latest run directory for the given scanner.

    Returns {} if we can't find it.
    """
    run_dir = get_latest_run_dir(scanner)
    if run_dir is None:
        return {}

    meta_path = run_dir / "metadata.json"
    if not meta_path.exists():
        return {}

    try:
        with meta_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}

    return data


def run_sast_runtime_benchmark(
    target_key: str,
    scanners: List[str],
) -> Dict[str, Any]:
    """
    Run each scanner for the given target and collect runtime metrics.

    Parameters
    ----------
    target_key: str
        Logical benchmark name (key in BENCHMARKS, e.g. "juice_shop").
    scanners: list[str]
        List of scanner names (e.g. ["semgrep", "snyk", "sonar", "aikido"]).

    Returns
    -------
    dict
        JSON-serializable summary of the benchmark run, e.g.:

        {
          "benchmark_target": "juice_shop",
          "timestamp": "...",
          "results": [
            {
              "scanner": "semgrep",
              "exit_code": 0,
              "wall_clock_seconds": 12.34,
              "run_id": "2025120101",
              "scan_time_seconds": 12.10,
            },
            ...
          ]
        }

    Notes
    -----
    - wall_clock_seconds is measured here around the full scanner command.
    - scan_time_seconds is taken from each tool's metadata.json:
        * Semgrep/Snyk/Sonar: usually the tool-reported scan duration.
        * Aikido: HTTP trigger latency for the /scan API call, not full engine time.
    """
    if target_key not in BENCHMARKS:
        raise ValueError(
            f"Unknown target '{target_key}'. "
            f"Valid options: {', '.join(sorted(BENCHMARKS.keys()))}"
        )

    summary_results: List[Dict[str, Any]] = []

    for scanner in scanners:
        print(f"\n▶️  Benchmarking scanner: {scanner} on target: {target_key}")

        # Build the same command sast_cli.py would use
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

        meta = read_metadata_from_run(scanner)

        # For most tools this is the scanner's own timing; for Aikido this is
        # the HTTP trigger time we store in scan_aikido.py (see its metadata block).
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

    benchmark_summary: Dict[str, Any] = {
        "benchmark_target": target_key,
        "timestamp": datetime.now().isoformat(),
        "results": summary_results,
    }
    return benchmark_summary


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
        output_root = Path("runs") / "benchmarks"

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
