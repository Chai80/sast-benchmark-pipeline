"""pipeline.analysis.unique_overview

Compute simple cross-tool "unique hotspot" signatures.

Context
-------
Some metrics want to compare tools on *where* they report issues, not just how
many. A common low-noise signature is:

  (normalized_file_path, OWASP_2021_canonical_code)

However, scanners are inconsistent about whether file paths are repo-relative
or include an extra repo-name prefix (e.g. "juice-shop/routes/a.ts").

This module normalizes file paths at analysis time to prevent false "uniques"
caused only by path formatting differences.

Design goals
------------
- Keep this module pure and dependency-light.
- Do not rewrite on-disk JSONs (no rescan needed).
- Keep scanner scripts "dumb"; fix comparability in analysis.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from pipeline.analysis.path_normalization import normalize_file_path
from pipeline.analysis.run_discovery import discover_latest_runs
from pipeline.core import ROOT_DIR as REPO_ROOT_DIR
from tools.classification_resolver import normalize_cwe_id, normalize_owasp_top10_code


Signature = Tuple[str, str]  # (file_path, owasp_code)


@dataclass(frozen=True)
class ToolInput:
    """Metadata + signatures for one tool's normalized output."""

    tool: str
    input_path: Path
    repo_name: Optional[str]
    run_id: Optional[str]
    scan_date: Optional[str]
    commit: Optional[str]
    finding_count: int
    raw_repo_prefix_paths: int
    signatures: Set[Signature]


def _as_list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


def _parse_tools_csv(raw: str | None) -> List[str]:
    if not raw:
        return []
    items = [t.strip() for t in raw.split(",")]
    return [t for t in items if t]


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object at {path}")
    return data


def _unwrap_cwe_to_owasp_map(cwe_to_owasp_map: Mapping[str, Any]) -> Mapping[str, Any]:
    inner = cwe_to_owasp_map.get("cwe_to_owasp")
    return inner if isinstance(inner, dict) else cwe_to_owasp_map


def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def canonical_owasp_2021_codes(
    finding: Mapping[str, Any],
    *,
    cwe_to_owasp_map: Mapping[str, Any],
) -> List[str]:
    """Return canonical OWASP Top 10 2021 codes for a finding.

    Strategy (in order):
    1) Prefer explicit canonical block if present (newer normalized outputs).
    2) Otherwise derive from CWE(s) using the shared MITRE mapping.

    Returns a list because a single CWE can map to multiple OWASP categories.
    """

    # 1) Preferred: explicit canonical field from newer normalized JSONs
    blk = finding.get("owasp_top_10_2021_canonical")
    if isinstance(blk, dict):
        codes = blk.get("codes")
        if isinstance(codes, list):
            out = []
            for c in codes:
                nc = normalize_owasp_top10_code(c, "2021")
                if nc:
                    out.append(nc)
            return _dedupe_preserve_order(out)

    # 2) Fallback: derive from CWE ids present on the finding
    raw_cwes: List[Any] = []
    if isinstance(finding.get("cwe_ids"), list):
        raw_cwes.extend(finding.get("cwe_ids") or [])
    if finding.get("cwe_id") is not None:
        raw_cwes.append(finding.get("cwe_id"))

    cwes: List[str] = []
    for raw in raw_cwes:
        ncwe = normalize_cwe_id(raw)
        if ncwe:
            cwes.append(ncwe)
    cwes = _dedupe_preserve_order(cwes)
    if not cwes:
        return []

    mapping = _unwrap_cwe_to_owasp_map(cwe_to_owasp_map)

    out: List[str] = []
    for cwe in cwes:
        entry = mapping.get(cwe)
        if not isinstance(entry, dict):
            continue
        o21 = entry.get("owasp_top_10_2021") or entry.get("owasp_2021") or entry.get("owasp2021")
        if isinstance(o21, dict):
            codes = o21.get("codes")
            if isinstance(codes, list):
                for c in codes:
                    nc = normalize_owasp_top10_code(c, "2021")
                    if nc:
                        out.append(nc)
        elif isinstance(o21, list):
            for c in o21:
                nc = normalize_owasp_top10_code(c, "2021")
                if nc:
                    out.append(nc)

    return _dedupe_preserve_order(out)


def hotspot_signatures_by_file(
    *,
    findings: Sequence[Mapping[str, Any]],
    repo_name: Optional[str],
    cwe_to_owasp_map: Mapping[str, Any],
) -> Set[Signature]:
    """Build (file, OWASP_2021_code) signatures for a list of findings."""
    sigs: Set[Signature] = set()
    for f in findings:
        raw_fp = f.get("file_path")
        if raw_fp is None:
            continue
        p = normalize_file_path(str(raw_fp), repo_name)
        if not p:
            continue

        codes = canonical_owasp_2021_codes(f, cwe_to_owasp_map=cwe_to_owasp_map)
        for code in codes:
            sigs.add((p, code))
    return sigs


def count_repo_prefix_paths(
    findings: Sequence[Mapping[str, Any]],
    *,
    repo_name: Optional[str],
) -> int:
    """Count findings whose (raw) file_path starts with "{repo_name}/".

    This is intended only as a quick sanity check when you suspect a tool is
    embedding the repo name in file paths.
    """
    if not repo_name:
        return 0
    prefix = repo_name.strip("/") + "/"
    n = 0
    for f in findings:
        fp = f.get("file_path")
        if not isinstance(fp, str):
            continue
        p = fp.replace("\\", "/")
        while p.startswith("./"):
            p = p[2:]
        p = p.lstrip("/")
        if p.startswith(prefix):
            n += 1
    return n


def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=(
            "Compute cross-tool unique hotspot signatures using the signature: "
            "(normalized_file_path, OWASP 2021 canonical code).\n\n"
            "You can either pass explicit normalized JSON file paths OR provide --repo to auto-"
            "discover the latest run per tool under runs/<tool>/<repo>/<run_id>/."
        )
    )

    ap.add_argument(
        "normalized_json",
        nargs="*",
        type=Path,
        help=(
            "Paths to <repo>.normalized.json files (one per tool). If omitted, use --repo "
            "to discover latest runs automatically."
        ),
    )

    ap.add_argument(
        "--repo",
        help=(
            "Repo name (directory under runs/<tool>/). If provided, the script discovers the "
            "latest run_id per tool automatically. Example: --repo juice-shop"
        ),
    )
    ap.add_argument(
        "--runs-dir",
        type=Path,
        default=REPO_ROOT_DIR / "runs",
        help="Base runs directory (default: <repo_root>/runs)",
    )
    ap.add_argument(
        "--tools",
        default="snyk,semgrep,sonar,aikido",
        help="Comma-separated tool list when using --repo (default: snyk,semgrep,sonar,aikido)",
    )
    ap.add_argument(
        "--allow-missing",
        action="store_true",
        help="If a tool has no runs, skip it instead of failing.",
    )

    ap.add_argument(
        "--cwe-map",
        type=Path,
        default=REPO_ROOT_DIR / "mappings" / "cwe_to_owasp_top10_mitre.json",
        help=(
            "Path to CWE->OWASP mapping JSON "
            "(default: <repo_root>/mappings/cwe_to_owasp_top10_mitre.json)"
        ),
    )

    ap.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        help="Write the full JSON report to this path.",
    )
    ap.add_argument(
        "--max-unique",
        type=int,
        default=25,
        help="For text output, show up to N unique files per tool (default: 25).",
    )

    return ap.parse_args()


def _extract_str(d: Any, key: str) -> Optional[str]:
    if isinstance(d, dict) and isinstance(d.get(key), str):
        return d.get(key)
    return None


def _read_tool_input(path: Path, *, cwe_map: Mapping[str, Any]) -> ToolInput:
    data = _load_json(path)
    tool = str(data.get("tool") or "unknown")

    target_repo = data.get("target_repo")
    repo_name = _extract_str(target_repo, "name")
    commit = _extract_str(target_repo, "commit")

    scan = data.get("scan")
    run_id = _extract_str(scan, "run_id")
    scan_date = _extract_str(scan, "scan_date")

    findings = _as_list(data.get("findings"))

    before = count_repo_prefix_paths(findings, repo_name=repo_name)
    sigs = hotspot_signatures_by_file(findings=findings, repo_name=repo_name, cwe_to_owasp_map=cwe_map)

    return ToolInput(
        tool=tool,
        input_path=path,
        repo_name=repo_name,
        run_id=run_id,
        scan_date=scan_date,
        commit=commit,
        finding_count=len(findings),
        raw_repo_prefix_paths=before,
        signatures=sigs,
    )


def _sig_sort_key(sig: Signature) -> tuple[str, str]:
    return sig[0], sig[1]


def _sig_id(sig: Signature) -> str:
    """Stable, human-readable signature id.

    We intentionally keep this *readable* (not a hash) so it can be copy/pasted
    into logs, spreadsheets, etc.
    """

    p, code = sig
    return f"{p}|{code}"


def _sig_to_dict(sig: Signature) -> Dict[str, str]:
    p, code = sig
    return {"signature": _sig_id(sig), "file": p, "code": code}


def _group_unique_by_file(sigs: Iterable[Signature]) -> List[Dict[str, Any]]:
    """Group a signature set into a compact "by file" view.

    Returns a list to preserve deterministic ordering.
    """

    by_file: Dict[str, Set[str]] = {}
    for fp, code in sigs:
        by_file.setdefault(fp, set()).add(code)

    out: List[Dict[str, Any]] = []
    for fp in sorted(by_file.keys()):
        codes = sorted(by_file[fp])
        out.append(
            {
                "file": fp,
                "codes": codes,
                # Convenience field for humans and downstream tooling.
                "signatures": [f"{fp}|{c}" for c in codes],
            }
        )
    return out


def build_hotspot_report(tool_inputs: Sequence[ToolInput]) -> Dict[str, Any]:
    """Build a JSON-serializable report from per-tool signature sets."""

    per_tool: Dict[str, ToolInput] = {}
    for ti in tool_inputs:
        if ti.tool in per_tool:
            raise ValueError(
                f"Duplicate tool name '{ti.tool}' detected. "
                "Pass only one normalized JSON per tool."
            )
        per_tool[ti.tool] = ti

    tools = sorted(per_tool.keys())
    if not tools:
        raise ValueError("No tools loaded; nothing to compare.")

    sig_sets = {t: per_tool[t].signatures for t in tools}
    union: Set[Signature] = set().union(*sig_sets.values())

    inter: Set[Signature] = set(sig_sets[tools[0]])
    for t in tools[1:]:
        inter &= sig_sets[t]


    # Sorted signature lists (used for reporting + downstream matrix generation)
    union_sorted = sorted(union, key=_sig_sort_key)
    inter_sorted = sorted(inter, key=_sig_sort_key)

    union_signatures = [_sig_to_dict(s) for s in union_sorted]
    intersection_signatures = [_sig_to_dict(s) for s in inter_sorted]

    # Unique signatures per tool (classic set-difference view)
    unique: Dict[str, List[Dict[str, str]]] = {}

    # Extra output shapes to make reports easier to read / consume without
    # changing the underlying comparison logic.
    unique_counts: Dict[str, int] = {}
    unique_flat: List[Dict[str, str]] = []
    unique_by_file: Dict[str, List[Dict[str, Any]]] = {}

    for t in tools:
        others_union = set().union(*(sig_sets[x] for x in tools if x != t))
        only: Set[Signature] = sig_sets[t] - others_union

        only_sorted = sorted(only, key=_sig_sort_key)
        unique[t] = [_sig_to_dict(s) for s in only_sorted]
        unique_counts[t] = len(only_sorted)

        # Flat list where each row carries its owning tool.
        for s in only_sorted:
            row = _sig_to_dict(s)
            unique_flat.append({"tool": t, **row})

        # Compact file-level view: file -> [Axx, Ayy, ...]
        unique_by_file[t] = _group_unique_by_file(only)

    # Deterministic ordering for the flat list
    unique_flat.sort(key=lambda r: (r.get("tool", ""), r.get("file", ""), r.get("code", "")))

    counts: Dict[str, int] = {t: len(sig_sets[t]) for t in tools}
    counts["union"] = len(union)
    counts["intersection"] = len(inter)

    # Repo name: pick the first non-empty one
    repo_name: str = "unknown"
    for t in tools:
        rn = per_tool[t].repo_name
        if rn:
            repo_name = rn
            break

    report_tools: Dict[str, Any] = {}
    for t in tools:
        ti = per_tool[t]
        report_tools[t] = {
            "input": str(ti.input_path),
            "run_id": ti.run_id,
            "scan_date": ti.scan_date,
            "commit": ti.commit,
            "finding_count": ti.finding_count,
            "signature_count": len(ti.signatures),
            "raw_paths_with_repo_prefix": ti.raw_repo_prefix_paths,
        }

    commits = sorted({c for c in (per_tool[t].commit for t in tools) if c})
    warnings: List[str] = []

    missing_commit_tools = [t for t in tools if not per_tool[t].commit]
    if missing_commit_tools:
        warnings.append(
            "Some tools did not provide commit metadata. "
            "Cross-tool comparisons may not be apples-to-apples. "
            f"Missing commit for: {', '.join(missing_commit_tools)}"
        )

    if len(commits) > 1:
        warnings.append(
            "Not all tools scanned the same commit. "
            "Cross-tool comparisons may not be apples-to-apples. "
            f"Commits observed: {', '.join(commits)}"
        )

    report: Dict[str, Any] = {
        "repo": repo_name,
        "signature_type": "(normalized_file_path, owasp_2021_code)",
        "tools": report_tools,
        "counts": counts,
        "union_signatures": union_signatures,
        "intersection_signatures": intersection_signatures,
        "unique": unique,
        # Convenience fields
        "unique_counts": unique_counts,
        "unique_flat": unique_flat,
        "unique_by_file": unique_by_file,
    }
    if warnings:
        report["warnings"] = warnings
    return report


def analyze_hotspots_from_files(
    paths: Sequence[Path],
    *,
    cwe_map_path: Path = REPO_ROOT_DIR / "mappings" / "cwe_to_owasp_top10_mitre.json",
) -> Dict[str, Any]:
    """Compute the unique-hotspots-by-file report from explicit JSON file paths."""
    cwe_map = _load_json(cwe_map_path)
    tool_inputs = [_read_tool_input(p, cwe_map=cwe_map) for p in paths]
    return build_hotspot_report(tool_inputs)


def analyze_latest_hotspots_for_repo(
    repo_name: str,
    *,
    tools: Sequence[str],
    runs_dir: Path = REPO_ROOT_DIR / "runs",
    cwe_map_path: Path = REPO_ROOT_DIR / "mappings" / "cwe_to_owasp_top10_mitre.json",
    allow_missing: bool = False,
) -> Dict[str, Any]:
    """Compute the report using the latest run per tool under the runs/ directory."""
    selected = discover_latest_runs(
        runs_dir=runs_dir,
        repo_name=repo_name,
        tools=tools,
        allow_missing=allow_missing,
    )
    ordered_paths = [selected[t].normalized_json for t in tools if t in selected]
    if not ordered_paths:
        raise ValueError("No tool runs discovered.")
    return analyze_hotspots_from_files(ordered_paths, cwe_map_path=cwe_map_path)


def main() -> None:
    args = _parse_args()

    if args.repo and args.normalized_json:
        raise SystemExit("Provide either --repo OR explicit normalized_json paths, not both.")
    if not args.repo and not args.normalized_json:
        raise SystemExit("Nothing to do. Provide --repo or one or more normalized_json paths.")

    if args.repo:
        tools = _parse_tools_csv(args.tools)
        if not tools:
            raise SystemExit("--tools resolved to an empty list.")
        report = analyze_latest_hotspots_for_repo(
            args.repo,
            tools=tools,
            runs_dir=args.runs_dir,
            cwe_map_path=args.cwe_map,
            allow_missing=args.allow_missing,
        )
    else:
        report = analyze_hotspots_from_files(args.normalized_json, cwe_map_path=args.cwe_map)

    # Optional: write report JSON to disk
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # Print
    if args.format == "json":
        print(json.dumps(report, indent=2))
        return

        # Human-readable output
    print_inputs(report)
    print_text_report(report, max_unique=args.max_unique)


def print_inputs(report: Mapping[str, Any]) -> None:
    """Pretty-print the per-tool input metadata from a hotspots report."""

    tools = sorted((report.get("tools") or {}).keys())

    print("\n== Inputs ==")
    for t in tools:
        info = (report.get("tools") or {}).get(t) or {}
        print(f"\n== {t} ==")
        print("Input file:", info.get("input"))
        if info.get("scan_date"):
            print("Scan date :", info.get("scan_date"))
        if info.get("run_id"):
            print("Run id    :", info.get("run_id"))
        if info.get("commit"):
            print("Commit    :", info.get("commit"))
        print("Findings  :", info.get("finding_count"))
        print("Signatures:", info.get("signature_count"))
        print("Raw paths with repo prefix:", info.get("raw_paths_with_repo_prefix"))


def print_text_report(report: Mapping[str, Any], *, max_unique: int = 25) -> None:
    """Pretty-print a hotspots-by-file report.

    This exists so the CLI can reuse the same formatting without duplicating
    printing logic (keeps things non-spaghetti).
    """

    tools = sorted((report.get("tools") or {}).keys())

    print("\n== Cross-tool summary ==")
    print("Repo:", report.get("repo"))
    print("Tools:", ", ".join(tools))
    print("Signature type:", report.get("signature_type"))

    counts = report.get("counts") or {}
    print("Union signatures       :", counts.get("union"))
    print("Intersection signatures:", counts.get("intersection"))

    unique = report.get("unique") or {}
    for t in tools:
        n_unique = len(unique.get(t) or [])
        print(f"Unique to {t:>8}: {n_unique}")

    warnings = report.get("warnings") or []
    for w in warnings:
        print("\n⚠️", w)

    max_unique = max(0, int(max_unique))
    if max_unique == 0:
        return

    unique_by_file = report.get("unique_by_file")
    if not isinstance(unique_by_file, dict):
        unique_by_file = {}

    for t in tools:
        items = unique_by_file.get(t) or []
        if not items:
            continue
        print(f"\n== Unique hotspots for {t} (showing up to {max_unique} files) ==")
        for row in items[:max_unique]:
            fp = row.get("file")
            codes = row.get("codes")
            if not isinstance(codes, list):
                codes = []
            codes_str = ", ".join(str(c) for c in codes)
            print(f"- {fp}: {codes_str}")



if __name__ == "__main__":
    main()
