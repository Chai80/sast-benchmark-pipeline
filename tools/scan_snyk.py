#!/usr/bin/env python3
"""
tools/scan_snyk.py

Runs Snyk Code (SARIF) for a repo and writes:
  runs/snyk/<repo_name>/<run_id>/
    - <repo_name>.sarif
    - metadata.json
    - <repo_name>.normalized.json

Recommended (package) invocation:
  python -m tools.scan_snyk --repo-url https://github.com/juice-shop/juice-shop

Still supported (direct script) invocation:
  python tools/scan_snyk.py --repo-url https://github.com/juice-shop/juice-shop
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Minimal bootstrap so this file can be executed directly while using
# clean package imports (no try/except import scaffolding).
# ---------------------------------------------------------------------------
if __package__ in (None, ""):
    # When running "python tools/scan_snyk.py", ensure repo root is importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.classification_resolver import resolve_owasp_and_cwe
from tools.core import (
    acquire_repo,
    build_run_metadata,
    create_run_dir_compat,
    load_cwe_to_owasp_map,
    normalize_repo_relative_path,
    read_json,
    read_line_content,
    run_cmd,
    which_or_raise,
    write_json,
)
from tools.normalize_common import (
    build_per_finding_metadata,
    build_scan_info,
    build_target_repo,
)

ROOT_DIR = Path(__file__).resolve().parents[1]
SNYK_BIN_FALLBACKS = ["/opt/homebrew/bin/snyk", "/usr/local/bin/snyk"]

# ---------------------------------------------------------------------------
# Small data structs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RunPaths:
    run_dir: Path
    raw_sarif: Path
    normalized: Path
    metadata: Path


def prepare_run_paths(output_root: str, repo_name: str) -> Tuple[str, RunPaths]:
    """
    Create run directory + standard file layout.

    Layout:
      runs/snyk/<repo_name>/<run_id>/
        - <repo_name>.sarif
        - metadata.json
        - <repo_name>.normalized.json
    """
    run_id, run_dir = create_run_dir_compat(Path(output_root) / repo_name)
    return run_id, RunPaths(
        run_dir=run_dir,
        raw_sarif=run_dir / f"{repo_name}.sarif",
        normalized=run_dir / f"{repo_name}.normalized.json",
        metadata=run_dir / "metadata.json",
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run Snyk Code scan and normalize results.")
    p.add_argument("--repo-url", help="Git repo URL to scan.")
    p.add_argument("--repo-path", help="Local repo path to scan (skip clone).")
    p.add_argument("--repos-dir", default="repos", help="Repos base dir (default: repos).")
    p.add_argument("--output-root", default="runs/snyk", help="Output root (default: runs/snyk).")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Snyk execution
# ---------------------------------------------------------------------------


def require_snyk_token() -> None:
    if not os.environ.get("SNYK_TOKEN"):
        raise SystemExit(
            "Missing SNYK_TOKEN environment variable.\n"
            "Set it in your shell or .env before running."
        )


def snyk_version(snyk_bin: str) -> str:
    res = run_cmd([snyk_bin, "--version"], print_stderr=False, print_stdout=False)
    return (res.stdout or res.stderr).strip() or "unknown"


def run_snyk_code_sarif(*, snyk_bin: str, repo_path: Path, out_sarif: Path) -> Tuple[int, float, str]:
    """
    Run:
      snyk code test --sarif --sarif-file-output <out_sarif>

    Returns: (exit_code, elapsed_seconds, command_str)
    """
    require_snyk_token()

    cmd = [
        snyk_bin,
        "code",
        "test",
        "--sarif",
        "--sarif-file-output",
        str(out_sarif),
    ]
    res = run_cmd(cmd, cwd=repo_path, print_stderr=True, print_stdout=True)
    return res.exit_code, res.elapsed_seconds, res.command_str


# ---------------------------------------------------------------------------
# Optional vendor mapping (small + isolated)
# ---------------------------------------------------------------------------

VendorRuleIndex = Dict[str, Dict[str, List[str]]]


def load_snyk_vendor_rule_index() -> VendorRuleIndex:
    """Load optional Snyk rule -> (OWASP-2021, CWE) mapping.

    Why this exists
    ---------------
    Snyk SARIF does not always include CWE/OWASP tags.
    This repo maintains an offline mapping file so we can still populate:
      - owasp_top_10_2021 (strong signal)
      - cwe_ids (so we can derive OWASP 2017/2021 via MITRE as fallback)

    Supported mapping file shapes
    -----------------------------
    1) Current repo schema (recommended):
         {"languages": {"python": {"Rule Name": {"cwe_ids": [...], "owasp_top_10_2021": [...]}, ...}}}
    2) Legacy flat map:
         {"RULE_ID": ["A03"], ...}
    3) Legacy list:
         {"rules": [{"id": "...", "name": "...", "owasp_2021": [...]}, ...]}
    """
    candidates = [
        ROOT_DIR / "mappings" / "snyk_rule_to_owasp_2021.json",
        ROOT_DIR / "mappings" / "snyk_rule_to_owasp_top10_2021.json",
        ROOT_DIR / "mappings" / "snyk_to_owasp_2021.json",
    ]

    def norm_key(s: str) -> str:
        return " ".join(s.strip().lower().replace("_", " ").split())

    def as_str_list(v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return [str(x) for x in v if x is not None]
        return []

    def put(idx: VendorRuleIndex, key: str, *, owasp2021: List[str], cwe_ids: List[str]) -> None:
        if not key:
            return
        if not (owasp2021 or cwe_ids):
            return
        idx[key] = {"owasp_top_10_2021": owasp2021, "cwe_ids": cwe_ids}

    for p in candidates:
        if not p.exists():
            continue
        try:
            data = read_json(p)
        except Exception:
            continue

        if not isinstance(data, dict):
            continue

        idx: VendorRuleIndex = {}

        # Shape 1: {"languages": {"python": {"Rule Name": {...}}}}
        languages = data.get("languages")
        if isinstance(languages, dict):
            for _lang, rules in languages.items():
                if not isinstance(rules, dict):
                    continue
                for rname, info in rules.items():
                    if not isinstance(rname, str) or not rname.strip():
                        continue
                    if not isinstance(info, dict):
                        continue
                    owasp2021 = as_str_list(
                        info.get("owasp_top_10_2021") or info.get("owasp_2021") or info.get("owasp2021")
                    )
                    cwe_ids = as_str_list(info.get("cwe_ids") or info.get("cwe") or info.get("cweIds"))
                    put(idx, rname, owasp2021=owasp2021, cwe_ids=cwe_ids)
                    put(idx, norm_key(rname), owasp2021=owasp2021, cwe_ids=cwe_ids)

        # Shape 2: flat map {"RULE_ID": ["A03"]} OR {"RULE_ID": {"owasp_2021": [...], ...}}
        for k, v in data.items():
            if not isinstance(k, str):
                continue
            if k in {"_meta", "aliases", "languages", "rules"}:
                continue
            if isinstance(v, list):
                put(idx, k, owasp2021=[str(x) for x in v if x is not None], cwe_ids=[])
            elif isinstance(v, dict):
                codes = as_str_list(v.get("owasp_2021") or v.get("owasp_top_10_2021") or v.get("owasp2021"))
                cwe_ids = as_str_list(v.get("cwe_ids") or v.get("cwe") or v.get("cweIds"))
                put(idx, k, owasp2021=codes, cwe_ids=cwe_ids)
                if isinstance(v.get("name"), str) and v.get("name").strip():
                    put(idx, norm_key(v["name"]), owasp2021=codes, cwe_ids=cwe_ids)

        # Shape 3: {"rules": [{"id": "...", "name": "...", ...}]}
        rules = data.get("rules")
        if isinstance(rules, list):
            for r in rules:
                if not isinstance(r, dict):
                    continue
                rid = r.get("id") or r.get("rule_id")
                name = r.get("name")
                codes = as_str_list(r.get("owasp_2021") or r.get("owasp_top_10_2021") or r.get("owasp2021"))
                cwe_ids = as_str_list(r.get("cwe_ids") or r.get("cwe") or r.get("cweIds"))
                if isinstance(rid, str) and rid.strip():
                    put(idx, rid.strip(), owasp2021=codes, cwe_ids=cwe_ids)
                if isinstance(name, str) and name.strip():
                    put(idx, name.strip(), owasp2021=codes, cwe_ids=cwe_ids)
                    put(idx, norm_key(name), owasp2021=codes, cwe_ids=cwe_ids)

        if not idx:
            # File exists but schema didn't match anything we recognize.
            # Don't fail the scan; just fall back to tags/CWE.
            continue

        return idx

    return {}


def load_snyk_vendor_owasp_2021_index() -> VendorRuleIndex:
    """Backwards-compatible alias."""
    return load_snyk_vendor_rule_index()


def vendor_rule_info(
    vendor_idx: VendorRuleIndex,
    rule_id: Optional[str],
    rule_name: Optional[str],
) -> Tuple[List[str], List[str]]:
    """Lookup (owasp2021_codes, cwe_ids) for a given Snyk rule."""
    if not vendor_idx:
        return [], []

    def norm_key(s: str) -> str:
        return " ".join(s.strip().lower().replace("_", " ").split())

    info: Optional[Dict[str, List[str]]] = None
    if rule_id and rule_id in vendor_idx:
        info = vendor_idx.get(rule_id)
    if info is None and rule_name:
        info = vendor_idx.get(rule_name) or vendor_idx.get(norm_key(rule_name))

    if not isinstance(info, dict):
        return [], []
    return info.get("owasp_top_10_2021") or [], info.get("cwe_ids") or []


# ---------------------------------------------------------------------------
# SARIF parsing (kept minimal)
# ---------------------------------------------------------------------------

_CWE_RE = re.compile(r"(CWE-\d+)", re.IGNORECASE)


def severity_from_level(level: Optional[str]) -> Optional[str]:
    if not level:
        return None
    lvl = str(level).strip().lower()
    if lvl == "error":
        return "HIGH"
    if lvl == "warning":
        return "MEDIUM"
    if lvl in ("note", "none"):
        return "LOW"
    return "MEDIUM"


def rules_by_id(run_obj: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rules = (((run_obj.get("tool") or {}).get("driver") or {}).get("rules")) or []
    out: Dict[str, Dict[str, Any]] = {}
    if isinstance(rules, list):
        for r in rules:
            if isinstance(r, dict) and isinstance(r.get("id"), str):
                out[r["id"]] = r
    return out


def rule_name(rule_def: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(rule_def, dict):
        return None
    if isinstance(rule_def.get("name"), str) and rule_def["name"].strip():
        return rule_def["name"].strip()
    sd = rule_def.get("shortDescription")
    if isinstance(sd, dict) and isinstance(sd.get("text"), str):
        return sd["text"].strip()
    return None


def collect_text_blobs(rule_def: Optional[Dict[str, Any]]) -> List[str]:
    if not isinstance(rule_def, dict):
        return []
    blobs: List[str] = []
    for path in (("help", "text"), ("fullDescription", "text"), ("shortDescription", "text"), ("name",)):
        cur: Any = rule_def
        for k in path:
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(k)
        if isinstance(cur, str) and cur.strip():
            blobs.append(cur.strip())
    return blobs


def extract_tags(rule_def: Optional[Dict[str, Any]], res: Dict[str, Any]) -> List[str]:
    tags: List[str] = []

    rp = (rule_def or {}).get("properties") if isinstance(rule_def, dict) else None
    if isinstance(rp, dict):
        tags += [str(x) for x in (rp.get("tags") or [])] if isinstance(rp.get("tags"), list) else []

    sp = res.get("properties")
    if isinstance(sp, dict):
        tags += [str(x) for x in (sp.get("tags") or [])] if isinstance(sp.get("tags"), list) else []

    tags += collect_text_blobs(rule_def)

    # dedupe while preserving order
    seen = set()
    out: List[str] = []
    for t in tags:
        tt = t.strip()
        if tt and tt not in seen:
            seen.add(tt)
            out.append(tt)
    return out


def extract_cwe_candidates(res: Dict[str, Any], rule_def: Optional[Dict[str, Any]], tags: List[str]) -> List[str]:
    cands: List[str] = []

    # from properties
    for obj in (res.get("properties"), (rule_def or {}).get("properties")):
        if not isinstance(obj, dict):
            continue
        for k in ("cwe", "cwe_id", "cweId", "cwe_ids", "cweIds", "cwes"):
            v = obj.get(k)
            if isinstance(v, str) and v.strip():
                cands.append(v.strip())
            elif isinstance(v, list):
                cands += [str(x) for x in v if x is not None]

    # from SARIF taxa (if present)
    taxa = res.get("taxa")
    if isinstance(taxa, list):
        for t in taxa:
            if isinstance(t, dict):
                for k in ("id", "name"):
                    v = t.get(k)
                    if isinstance(v, str) and "CWE-" in v:
                        cands.append(v)

    # from tags/text blobs
    for t in tags:
        m = _CWE_RE.search(t)
        if m:
            cands.append(m.group(1).upper())

    # dedupe
    seen = set()
    out: List[str] = []
    for c in cands:
        cc = str(c).strip()
        if cc and cc not in seen:
            seen.add(cc)
            out.append(cc)
    return out


def primary_location(repo_path: Path, res: Dict[str, Any]) -> Tuple[Optional[str], Optional[int], Optional[int], Optional[str]]:
    locs = res.get("locations") or []
    loc0 = locs[0] if isinstance(locs, list) and locs and isinstance(locs[0], dict) else {}
    phys = loc0.get("physicalLocation") if isinstance(loc0, dict) else None
    phys = phys if isinstance(phys, dict) else {}
    artifact = phys.get("artifactLocation") if isinstance(phys, dict) else None
    artifact = artifact if isinstance(artifact, dict) else {}
    uri = artifact.get("uri") if isinstance(artifact, dict) else None

    fp = normalize_repo_relative_path(repo_path, uri if isinstance(uri, str) else None)

    region = phys.get("region") if isinstance(phys, dict) else None
    region = region if isinstance(region, dict) else {}

    start = region.get("startLine")
    end = region.get("endLine") or start

    line_content = read_line_content(repo_path, fp, int(start)) if fp and start else None
    return fp, int(start) if start else None, int(end) if end else None, line_content


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def normalize_sarif(
    *,
    repo_path: Path,
    raw_sarif_path: Path,
    metadata: Dict[str, Any],
    vendor_idx: VendorRuleIndex,
    cwe_to_owasp_map: Dict[str, Any],
    normalized_path: Path,
) -> None:
    # Align header blocks with other scanners (Sonar/Aikido) using normalize_common.
    target_repo = build_target_repo(metadata)
    scan_info = build_scan_info(metadata, raw_sarif_path)
    per_finding_metadata = build_per_finding_metadata(
        tool="snyk",
        tool_version=metadata.get("scanner_version"),
        target_repo=target_repo,
        scan_info=scan_info,
    )

    if not raw_sarif_path.exists():
        write_json(
            normalized_path,
            {
                "schema_version": "1.1",
                "tool": "snyk",
                "tool_version": metadata.get("scanner_version"),
                "target_repo": target_repo,
                "scan": scan_info,
                "run_metadata": metadata,
                "findings": [],
            },
        )
        return

    sarif = read_json(raw_sarif_path)
    runs = sarif.get("runs") or []
    run0 = runs[0] if isinstance(runs, list) and runs and isinstance(runs[0], dict) else {}
    rmap = rules_by_id(run0)
    results = run0.get("results") or []

    findings: List[Dict[str, Any]] = []
    for res in results if isinstance(results, list) else []:
        if not isinstance(res, dict):
            continue

        rid = res.get("ruleId") if isinstance(res.get("ruleId"), str) else None
        rdef = rmap.get(rid) if rid else None
        rname = rule_name(rdef)

        fp, start, end, line_content = primary_location(repo_path, res)
        sev = severity_from_level(res.get("level"))
        msg = res.get("message")
        title = msg.get("text") if isinstance(msg, dict) and isinstance(msg.get("text"), str) else (rname or rid)

        tags = extract_tags(rdef, res)
        cwe_candidates = extract_cwe_candidates(res, rdef, tags)

        # Vendor mapping (offline) can add OWASP-2021 codes and CWE IDs.
        vendor_codes, vendor_cwes = vendor_rule_info(vendor_idx, rid, rname)
        if vendor_cwes:
            cwe_candidates = cwe_candidates + vendor_cwes

        cls = resolve_owasp_and_cwe(
            tags=tags,
            cwe_candidates=cwe_candidates,
            vendor_owasp_2021_codes=vendor_codes,
            cwe_to_owasp_map=cwe_to_owasp_map,
            allow_2017_from_tags=True,  # parity with Semgrep, enables 2017 derivation
        )

        findings.append(
            {
                "metadata": per_finding_metadata,
                "finding_id": f"snyk:{rid}:{fp}:{start}",
                "rule_id": rid,
                "title": title,
                "severity": sev,
                "file_path": fp,
                "line_number": start,
                "end_line_number": end,
                "line_content": line_content,
                "cwe_id": cls.get("cwe_id"),
                "cwe_ids": cls.get("cwe_ids") or [],
                "vuln_class": None,
                "owasp_top_10_2017": cls.get("owasp_top_10_2017"),
                "owasp_top_10_2021": cls.get("owasp_top_10_2021"),
                "vendor": {"raw_result": res},
            }
        )

    write_json(
        normalized_path,
        {
            "schema_version": "1.1",
            "tool": "snyk",
            "tool_version": metadata.get("scanner_version"),
            "target_repo": target_repo,
            "scan": scan_info,
            "run_metadata": metadata,
            "findings": findings,
        },
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    args = parse_args()
    if not args.repo_url and not args.repo_path:
        raise SystemExit("Provide --repo-url or --repo-path.")

    repo = acquire_repo(repo_url=args.repo_url, repo_path=args.repo_path, repos_dir=args.repos_dir)

    snyk_bin = which_or_raise("snyk", fallbacks=SNYK_BIN_FALLBACKS)

    run_id, paths = prepare_run_paths(args.output_root, repo.repo_name)

    # Run Snyk
    exit_code, elapsed, cmd_str = run_snyk_code_sarif(
        snyk_bin=snyk_bin,
        repo_path=repo.repo_path,
        out_sarif=paths.raw_sarif,
    )

    # Metadata
    meta = build_run_metadata(
        scanner="snyk",
        scanner_version=snyk_version(snyk_bin),
        repo=repo,
        run_id=run_id,
        command_str=cmd_str,
        scan_time_seconds=elapsed,
        exit_code=exit_code,
    )
    write_json(paths.metadata, meta)

    # Normalize
    cwe_map = load_cwe_to_owasp_map()
    vendor_idx = load_snyk_vendor_owasp_2021_index()
    normalize_sarif(
        repo_path=repo.repo_path,
        raw_sarif_path=paths.raw_sarif,
        metadata=meta,
        vendor_idx=vendor_idx,
        cwe_to_owasp_map=cwe_map,
        normalized_path=paths.normalized,
    )

    print("📄 Raw SARIF saved to:", paths.raw_sarif)
    print("📄 Metadata saved to:", paths.metadata)
    print("📄 Normalized JSON saved to:", paths.normalized)


if __name__ == "__main__":
    main()
