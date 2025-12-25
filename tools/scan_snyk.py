#!/usr/bin/env python3
"""
tools/scan_snyk.py

Runs Snyk Code (SARIF) for a repo and writes:
  runs/snyk/<repo_name>/<run_id>/
    - <repo_name>.sarif
    - metadata.json
    - <repo_name>.normalized.json

This file stays small by pushing shared plumbing into tools/core.py.
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---- Robust imports (script execution) ----
try:
    from core import (
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
except ImportError:
    from tools.core import (  # type: ignore
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

try:
    from classification_resolver import resolve_owasp_and_cwe
except ImportError:
    from tools.classification_resolver import resolve_owasp_and_cwe  # type: ignore


ROOT_DIR = Path(__file__).resolve().parents[1]


# ----------------------------
# CLI
# ----------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run Snyk Code scan and normalize results.")
    p.add_argument("--repo-url", help="Git repo URL to scan.")
    p.add_argument("--repo-path", help="Local repo path to scan (skip clone).")
    p.add_argument("--repos-dir", default="repos", help="Repos base dir (default: repos).")
    p.add_argument("--output-root", default="runs/snyk", help="Output root (default: runs/snyk).")
    return p.parse_args()


# ----------------------------
# Snyk execution
# ----------------------------

def require_snyk_token() -> None:
    if not os.environ.get("SNYK_TOKEN"):
        raise SystemExit(
            "Missing SNYK_TOKEN environment variable.\n"
            "Set it in your shell or .env before running."
        )


def snyk_version(snyk_bin: str) -> str:
    res = run_cmd([snyk_bin, "--version"], print_stderr=False, print_stdout=False)
    return (res.stdout or res.stderr).strip() or "unknown"


def run_snyk_code_sarif(repo_path: Path, out_sarif: Path) -> Tuple[int, float, str]:
    require_snyk_token()
    snyk_bin = which_or_raise("snyk", fallbacks=["/opt/homebrew/bin/snyk", "/usr/local/bin/snyk"])

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


# ----------------------------
# Optional vendor mapping (small + isolated)
# ----------------------------

def load_snyk_vendor_owasp_2021_index() -> Dict[str, List[str]]:
    """
    Optional: if you maintain a Snyk rule -> OWASP 2021 mapping file.
    If none exists, return {} and classification will rely on CWE mapping + tags.
    """
    candidates = [
        ROOT_DIR / "mappings" / "snyk_rule_to_owasp_2021.json",
        ROOT_DIR / "mappings" / "snyk_rule_to_owasp_top10_2021.json",
        ROOT_DIR / "mappings" / "snyk_to_owasp_2021.json",
    ]

    def norm(s: str) -> str:
        return " ".join(s.strip().lower().replace("_", " ").split())

    idx: Dict[str, List[str]] = {}
    for p in candidates:
        if not p.exists():
            continue
        try:
            data = read_json(p)
        except Exception:
            return {}

        if not isinstance(data, dict):
            return {}

        # Shape A: {"RULE_ID": ["A03"], ...} OR {"RULE_ID": {"owasp_2021":[...]}}
        for k, v in data.items():
            if isinstance(k, str):
                if isinstance(v, list):
                    idx[k] = [str(x) for x in v]
                elif isinstance(v, dict):
                    codes = v.get("owasp_2021") or v.get("owasp_top_10_2021") or v.get("owasp2021")
                    if isinstance(codes, list):
                        idx[k] = [str(x) for x in codes]
                    if isinstance(v.get("name"), str) and isinstance(codes, list):
                        idx[norm(v["name"])] = [str(x) for x in codes]

        # Shape B: {"rules":[{"id":"...", "name":"...", "owasp_2021":[...]}]}
        rules = data.get("rules")
        if isinstance(rules, list):
            for r in rules:
                if not isinstance(r, dict):
                    continue
                rid = r.get("id") or r.get("rule_id")
                name = r.get("name")
                codes = r.get("owasp_2021") or r.get("owasp_top_10_2021") or r.get("owasp2021")
                if isinstance(codes, str):
                    codes = [codes]
                if isinstance(codes, list):
                    if isinstance(rid, str) and rid:
                        idx[rid] = [str(x) for x in codes]
                    if isinstance(name, str) and name.strip():
                        idx[norm(name)] = [str(x) for x in codes]

        return idx

    return {}


def vendor_owasp_2021_codes(vendor_idx: Dict[str, List[str]], rule_id: Optional[str], rule_name: Optional[str]) -> List[str]:
    if not vendor_idx:
        return []
    if rule_id and rule_id in vendor_idx:
        return vendor_idx[rule_id]
    if rule_name:
        key = " ".join(rule_name.strip().lower().replace("_", " ").split())
        return vendor_idx.get(key, [])
    return []


# ----------------------------
# SARIF parsing (kept minimal)
# ----------------------------

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
    locs = res.get("locations")
    if not (isinstance(locs, list) and locs):
        return None, None, None, None

    pl = (locs[0].get("physicalLocation") or {}) if isinstance(locs[0], dict) else {}
    if not isinstance(pl, dict):
        return None, None, None, None

    artifact = pl.get("artifactLocation") or {}
    region = pl.get("region") or {}

    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    fp = normalize_repo_relative_path(repo_path, uri if isinstance(uri, str) else None)

    start = region.get("startLine") if isinstance(region, dict) else None
    end = region.get("endLine") if isinstance(region, dict) else None
    if end is None:
        end = start

    line_content = read_line_content(repo_path, fp, int(start)) if fp and start else None
    return fp, int(start) if start else None, int(end) if end else None, line_content


def normalize_sarif(
    repo_path: Path,
    repo_name: str,
    repo_url: Optional[str],
    commit: Optional[str],
    raw_sarif_path: Path,
    metadata: Dict[str, Any],
    vendor_idx: Dict[str, List[str]],
    cwe_to_owasp_map: Dict[str, Any],
    normalized_path: Path,
) -> None:
    target_repo = {"name": repo_name, "url": repo_url, "commit": commit}
    scan_info = {
        "tool": "snyk",
        "run_id": metadata.get("run_id"),
        "timestamp": metadata.get("timestamp"),
        "command": metadata.get("command"),
        "scan_time_seconds": metadata.get("scan_time_seconds"),
        "exit_code": metadata.get("exit_code"),
    }
    per_finding_metadata = {"tool": "snyk", "tool_version": metadata.get("scanner_version"), "target_repo": target_repo, "scan": scan_info}

    if not raw_sarif_path.exists():
        write_json(normalized_path, {
            "schema_version": "1.1",
            "tool": "snyk",
            "tool_version": metadata.get("scanner_version"),
            "target_repo": target_repo,
            "scan": scan_info,
            "run_metadata": metadata,
            "findings": [],
        })
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
        vendor_codes = vendor_owasp_2021_codes(vendor_idx, rid, rname)

        cls = resolve_owasp_and_cwe(
            tags=tags,
            cwe_candidates=cwe_candidates,
            vendor_owasp_2021_codes=vendor_codes,
            cwe_to_owasp_map=cwe_to_owasp_map,
            allow_2017_from_tags=True,  # parity with Semgrep, enables 2017 derivation
        )

        findings.append({
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
        })

    write_json(normalized_path, {
        "schema_version": "1.1",
        "tool": "snyk",
        "tool_version": metadata.get("scanner_version"),
        "target_repo": target_repo,
        "scan": scan_info,
        "run_metadata": metadata,
        "findings": findings,
    })


# ----------------------------
# Main
# ----------------------------

def main() -> None:
    args = parse_args()
    if not args.repo_url and not args.repo_path:
        raise SystemExit("Provide --repo-url or --repo-path.")

    repo = acquire_repo(repo_url=args.repo_url, repo_path=args.repo_path, repos_dir=args.repos_dir)

    run_id, run_dir = create_run_dir_compat(Path(args.output_root) / repo.repo_name)
    raw_sarif_path = run_dir / f"{repo.repo_name}.sarif"
    normalized_path = run_dir / f"{repo.repo_name}.normalized.json"
    metadata_path = run_dir / "metadata.json"

    # Run Snyk
    exit_code, elapsed, cmd_str = run_snyk_code_sarif(repo.repo_path, raw_sarif_path)

    # Build metadata (shared + safe)
    snyk_bin = which_or_raise("snyk", fallbacks=["/opt/homebrew/bin/snyk", "/usr/local/bin/snyk"])
    meta = build_run_metadata(
        scanner="snyk",
        scanner_version=snyk_version(snyk_bin),
        repo=repo,
        run_id=run_id,
        command_str=cmd_str,
        scan_time_seconds=elapsed,
        exit_code=exit_code,
    )
    write_json(metadata_path, meta)

    # Normalize
    cwe_map = load_cwe_to_owasp_map()
    vendor_idx = load_snyk_vendor_owasp_2021_index()
    normalize_sarif(
        repo_path=repo.repo_path,
        repo_name=repo.repo_name,
        repo_url=repo.repo_url,
        commit=repo.commit,
        raw_sarif_path=raw_sarif_path,
        metadata=meta,
        vendor_idx=vendor_idx,
        cwe_to_owasp_map=cwe_map,
        normalized_path=normalized_path,
    )

    print("📄 Raw SARIF saved to:", raw_sarif_path)
    print("📄 Metadata saved to:", metadata_path)
    print("📄 Normalized JSON saved to:", normalized_path)


if __name__ == "__main__":
    main()
