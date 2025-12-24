#!/usr/bin/env python3
"""
tools/scan_snyk.py

Snyk Code pipeline script for the sast-benchmark-pipeline.

Design goals
- Keep this file readable and mostly orchestration + SARIF parsing.
- Reuse normalize_common.py for consistent normalized JSON headers/writing.
- Centralize OWASP/CWE resolution policy in tools/classification_resolver.py so:
    * Snyk stays small
    * Semgrep/Aikido can reuse the exact same OWASP/CWE logic

Classification sources for Snyk
- OWASP 2021: tags -> Snyk rule-doc mapping (offline) -> MITRE CWE->OWASP fallback
- OWASP 2017: MITRE CWE->OWASP (Snyk vendor mapping usually doesn't include 2017)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

from normalize_common import (
    build_per_finding_metadata,
    build_scan_info,
    build_target_repo,
    read_line_content,
    write_json,
)
from run_utils import ROOT_DIR, clone_repo, create_run_dir, get_commit_author_info, get_git_commit

from classification_resolver import resolve_owasp_and_cwe


# -----------------------------
# CLI + env
# -----------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run Snyk Code and emit normalized JSON.")
    p.add_argument("--repo-url", help="Git URL of repo to scan.")
    p.add_argument("--output-root", default="runs/snyk", help="Root folder to store outputs (default: runs/snyk).")
    p.add_argument("--org", default=None, help="Optional Snyk org id/slug to use with --org.")
    p.add_argument(
        "--severity-threshold",
        default=None,
        choices=["low", "medium", "high"],
        help="Optional Snyk severity threshold (low|medium|high).",
    )
    p.add_argument(
        "--mappings-dir",
        default="mappings",
        help="Directory containing mapping JSONs (default: mappings). Relative paths are anchored under repo root.",
    )
    args = p.parse_args()
    if not args.repo_url:
        args.repo_url = input("Enter Git repo URL to scan: ").strip()
    return args


def ensure_snyk_token() -> None:
    if not os.getenv("SNYK_TOKEN"):
        print(
            "ERROR: SNYK_TOKEN is not set.\n"
            "Add it to your .env or export it in your shell before running.",
            file=sys.stderr,
        )
        raise SystemExit(1)


def get_snyk_version() -> str:
    try:
        out = subprocess.check_output(["snyk", "--version"], text=True)
        return out.strip()
    except Exception:
        return "unknown"


# -----------------------------
# Mapping loaders (optional)
# -----------------------------

def _load_json(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def load_cwe_to_owasp_map(mappings_dir: Path) -> dict:
    """
    Load the CWE -> OWASP Top 10 mapping.

    We *prefer* a conventional file name (cwe_to_owasp_top10_mitre.json), but we also
    support "whatever name" JSON files in the mappings directory as long as they contain
    a mapping payload.

    Accepted shapes:
      - {"_meta": ..., "cwe_to_owasp": {...}}
      - {"cwe_to_owasp": {...}}
      - {...} (already the mapping dict keyed by "CWE-xxx")
    """
    candidates = [
        mappings_dir / "cwe_to_owasp_top10_mitre.json",
        ROOT_DIR / "mappings" / "cwe_to_owasp_top10_mitre.json",
    ]

    # 1) Try conventional candidates first
    for p in candidates:
        if p.exists():
            data = _load_json(p)
            if isinstance(data, dict) and data:
                return data

    # 2) Fallback: scan mappings_dir for a file that *contains* cwe_to_owasp payload
    scan_dirs = [mappings_dir, ROOT_DIR / "mappings"]
    for d in scan_dirs:
        try:
            if not d.exists():
                continue
            for p in sorted(d.glob("*.json")):
                data = _load_json(p)
                if not isinstance(data, dict) or not data:
                    continue
                if "cwe_to_owasp" in data and isinstance(data.get("cwe_to_owasp"), dict):
                    return data
                # Some mapping files are *just* the dict keyed by CWE IDs
                if any(k.startswith("CWE-") for k in data.keys()):
                    # Heuristic: treat as mapping dict only if at least one value has owasp_top_10_* keys
                    sample_val = next(iter(data.values()), None)
                    if isinstance(sample_val, dict) and ("owasp_top_10_2017" in sample_val or "owasp_top_10_2021" in sample_val):
                        return data
        except Exception:
            continue

    return {}



def load_snyk_rule_to_owasp_2021_map(mappings_dir: Path) -> dict:
    """
    Load the Snyk rule -> OWASP 2021 mapping.

    Preferred file name: snyk_rule_to_owasp_2021.json
    Expected shape (generated by our project):
      {"_meta": ..., "aliases": {...}, "languages": {...}}

    Fallback behavior:
      - scan all *.json in mappings directories and pick the first dict that contains
        an "aliases" or "languages" section with OWASP codes.
    """
    candidates = [
        mappings_dir / "snyk_rule_to_owasp_2021.json",
        ROOT_DIR / "mappings" / "snyk_rule_to_owasp_2021.json",
    ]
    for p in candidates:
        if p.exists():
            data = _load_json(p)
            if isinstance(data, dict) and data:
                return data

    scan_dirs = [mappings_dir, ROOT_DIR / "mappings"]
    for d in scan_dirs:
        try:
            if not d.exists():
                continue
            for p in sorted(d.glob("*.json")):
                data = _load_json(p)
                if not isinstance(data, dict) or not data:
                    continue
                if isinstance(data.get("aliases"), dict) or isinstance(data.get("languages"), dict):
                    return data
        except Exception:
            continue

    return {}



def _norm_rule_name(s: Optional[str]) -> str:
    if not s:
        return ""
    return " ".join(s.strip().lower().split())


def build_snyk_rule_index(vendor_map: dict) -> Dict[str, Dict[str, dict]]:
    """
    Build index: {lang: {normalized_rule_name: entry}}
    Where entry is the mapping row from vendor_map["languages"][lang][rule_name].
    """
    index: Dict[str, Dict[str, dict]] = {}
    languages = vendor_map.get("languages") if isinstance(vendor_map, dict) else None
    if not isinstance(languages, dict):
        return index

    for lang, rules in languages.items():
        if not isinstance(rules, dict):
            continue
        bucket: Dict[str, dict] = {}
        for rule_name, entry in rules.items():
            if isinstance(rule_name, str) and isinstance(entry, dict):
                bucket[_norm_rule_name(rule_name)] = entry
        index[str(lang).lower()] = bucket
    return index


def lookup_snyk_vendor_owasp_2021(
    *,
    vendor_map: dict,
    vendor_index: Dict[str, Dict[str, dict]],
    language: Optional[str],
    rule_name: Optional[str],
) -> Tuple[List[str], Optional[dict]]:
    """
    Return (owasp_2021_codes, vendor_entry) for the given language + rule_name.
    """
    if not language or not rule_name:
        return [], None

    lang = str(language).lower()
    aliases = vendor_map.get("aliases") if isinstance(vendor_map, dict) else None
    if isinstance(aliases, dict) and lang in aliases:
        lang = aliases.get(lang) or lang

    entry = (vendor_index.get(lang) or {}).get(_norm_rule_name(rule_name))
    if not isinstance(entry, dict):
        return [], None

    codes = entry.get("owasp_top_10_2021") or entry.get("owasp_2021") or entry.get("owasp")
    if not isinstance(codes, list):
        return [], entry

    return [str(c) for c in codes if c is not None], entry


# -----------------------------
# Snyk execution
# -----------------------------

def run_snyk_scan(
    *,
    repo_path: Path,
    raw_results_path: Path,
    org: Optional[str],
    severity_threshold: Optional[str],
) -> Tuple[int, float, str, str, str]:
    """
    Run 'snyk code test' and write JSON output to raw_results_path.
    Returns (exit_code, elapsed_seconds, command_str).
    """
    cmd: List[str] = [
        "snyk",
        "code",
        "test",
        "--quiet",
        "--json-file-output",
        str(raw_results_path),
    ]
    if org:
        cmd.extend(["--org", org])
    if severity_threshold:
        cmd.extend(["--severity-threshold", severity_threshold])

    t0 = time.time()
    proc = subprocess.run(cmd, cwd=str(repo_path), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    elapsed = time.time() - t0
    return int(proc.returncode), float(elapsed), " ".join(cmd), (proc.stdout or ""), (proc.stderr or "")


def build_run_metadata(
    *,
    repo_path: Path,
    repo_name: str,
    repo_url: str,
    run_id: str,
    exit_code: int,
    elapsed: float,
    command_str: str,
    stdout: str = "",
    stderr: str = "",
) -> dict:
    commit = get_git_commit(repo_path)
    author_info = get_commit_author_info(repo_path, commit)

    return {
        "tool": "snyk",
        "repo_name": repo_name,
        "repo_url": repo_url,
        "repo_commit": commit,
        **author_info,
        "run_id": run_id,
        "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "command": command_str,
        "scan_time_seconds": elapsed,
        "exit_code": exit_code,
        "scanner_version": get_snyk_version(),
        "scanner_stdout_tail": (stdout[-4000:] if isinstance(stdout, str) else ""),
        "scanner_stderr_tail": (stderr[-4000:] if isinstance(stderr, str) else ""),
    }


# -----------------------------
# Normalization
# -----------------------------

def _build_rules_by_id(run_obj: dict) -> Dict[str, dict]:
    rules_by_id: Dict[str, dict] = {}
    driver = (((run_obj.get("tool") or {}).get("driver")) if isinstance(run_obj.get("tool"), dict) else {}) or {}
    rules = driver.get("rules") or []
    if isinstance(rules, list):
        for r in rules:
            if isinstance(r, dict) and isinstance(r.get("id"), str):
                rules_by_id[r["id"]] = r
    return rules_by_id


def _rule_name(rule_def: Optional[dict]) -> Optional[str]:
    if not isinstance(rule_def, dict):
        return None
    # SARIF rules can put human name in "name" or description text
    if isinstance(rule_def.get("name"), str) and rule_def["name"].strip():
        return rule_def["name"].strip()
    sd = rule_def.get("shortDescription")
    if isinstance(sd, dict) and isinstance(sd.get("text"), str) and sd["text"].strip():
        return sd["text"].strip()
    fd = rule_def.get("fullDescription")
    if isinstance(fd, dict) and isinstance(fd.get("text"), str) and fd["text"].strip():
        return fd["text"].strip()
    return None


def _severity_from_level(level: Any) -> str:
    if isinstance(level, str):
        if level == "error":
            return "high"
        if level == "warning":
            return "medium"
        if level == "note":
            return "low"
    return "medium"


def _extract_tags(rule_def: Optional[dict], res: dict) -> List[str]:
    tags: List[str] = []

    def add_from_props(props: Any) -> None:
        if not isinstance(props, dict):
            return
        t = props.get("tags")
        if isinstance(t, list):
            for x in t:
                if isinstance(x, str) and x.strip():
                    tags.append(x.strip())

    if isinstance(rule_def, dict):
        add_from_props(rule_def.get("properties"))
    add_from_props(res.get("properties"))

    # stable unique preserving order
    seen = set()
    out: List[str] = []
    for t in tags:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _extract_cwe_candidates(*dicts_or_lists: Any) -> List[Any]:
    """
    Grab common CWE fields from multiple dict-like sources.
    We intentionally return "raw candidates" (strings/ints/etc) and let the resolver normalize.
    """
    out: List[Any] = []
    for obj in dicts_or_lists:
        if isinstance(obj, dict):
            for k in ("cwe_ids", "cweIds", "cwe", "cwe_id", "cweId"):
                v = obj.get(k)
                if isinstance(v, list):
                    out.extend(v)
                elif v is not None:
                    out.append(v)
        elif isinstance(obj, list):
            out.extend(obj)
        elif obj is not None:
            out.append(obj)
    return out


def normalize_snyk_results(
    *,
    repo_path: Path,
    raw_results_path: Path,
    metadata: dict,
    normalized_path: Path,
    cwe_to_owasp_map: dict,
    snyk_rule_to_owasp_2021_map: dict,
    snyk_rule_index: Dict[str, Dict[str, dict]],
) -> None:
    """
    Normalize Snyk SARIF-ish JSON into schema v1.1 + OWASP/CWE enrichment.

    Output keys added compared to the older samples:
      - cwe_ids
      - owasp_top_10_2017
      - owasp_top_10_2021
      - vuln_class
    """
    target_repo = build_target_repo(metadata)
    scan_info = build_scan_info(metadata, raw_results_path)
    per_finding_meta = build_per_finding_metadata(
        tool="snyk",
        tool_version=metadata.get("scanner_version"),
        target_repo=target_repo,
        scan_info=scan_info,
    )

    # Missing raw results -> still emit a valid normalized doc
    if not raw_results_path.exists():
        normalized = {
            "schema_version": "1.1",
            "tool": "snyk",
            "tool_version": metadata.get("scanner_version"),
            "target_repo": target_repo,
            "scan": scan_info,
            "run_metadata": metadata,
            "findings": [],
        }
        write_json(normalized_path, normalized)
        return

    try:
        raw = json.loads(raw_results_path.read_text(encoding="utf-8"))
    except Exception:
        raw = {}

    runs = raw.get("runs")
    if not isinstance(runs, list) or not runs:
        normalized = {
            "schema_version": "1.1",
            "tool": "snyk",
            "tool_version": metadata.get("scanner_version"),
            "target_repo": target_repo,
            "scan": scan_info,
            "run_metadata": metadata,
            "findings": [],
        }
        write_json(normalized_path, normalized)
        return

    run0 = runs[0] if isinstance(runs[0], dict) else {}
    rules_by_id = _build_rules_by_id(run0)
    results = run0.get("results") or []
    if not isinstance(results, list):
        results = []

    # Cache vendor lookups per rule_id
    vendor_ctx: Dict[str, Dict[str, Any]] = {}
    for rid, rdef in rules_by_id.items():
        language = rid.split("/", 1)[0] if isinstance(rid, str) and "/" in rid else None
        rname = _rule_name(rdef)
        v_codes, v_entry = lookup_snyk_vendor_owasp_2021(
            vendor_map=snyk_rule_to_owasp_2021_map,
            vendor_index=snyk_rule_index,
            language=language,
            rule_name=rname,
        )
        vendor_ctx[rid] = {"language": language, "rule_name": rname, "vendor_codes": v_codes, "vendor_entry": v_entry}

    findings: List[dict] = []

    for res in results:
        if not isinstance(res, dict):
            continue

        rule_id = res.get("ruleId") if isinstance(res.get("ruleId"), str) else None
        rule_def = rules_by_id.get(rule_id) if rule_id else None
        ctx = vendor_ctx.get(rule_id or "", {})
        rule_name = ctx.get("rule_name") or _rule_name(rule_def) or rule_id

        severity = _severity_from_level(res.get("level"))

        # title/message
        title = None
        msg_obj = res.get("message")
        if isinstance(msg_obj, dict) and isinstance(msg_obj.get("text"), str):
            title = msg_obj.get("text")
        if not title and isinstance(rule_def, dict):
            sd = rule_def.get("shortDescription")
            if isinstance(sd, dict) and isinstance(sd.get("text"), str):
                title = sd.get("text")
        if not title:
            title = "Snyk finding"

        # location
        file_path: Optional[str] = None
        line: Optional[int] = None
        end_line: Optional[int] = None

        locs = res.get("locations") or []
        if isinstance(locs, list) and locs:
            loc0 = locs[0]
            if isinstance(loc0, dict):
                phys = (loc0.get("physicalLocation") or {}) if isinstance(loc0.get("physicalLocation"), dict) else {}
                artifact = (phys.get("artifactLocation") or {}) if isinstance(phys.get("artifactLocation"), dict) else {}
                uri = artifact.get("uri")
                if isinstance(uri, str):
                    file_path = uri
                region = (phys.get("region") or {}) if isinstance(phys.get("region"), dict) else {}
                sl = region.get("startLine")
                el = region.get("endLine")
                try:
                    line = int(sl) if sl is not None else None
                except Exception:
                    line = None
                try:
                    end_line = int(el) if el is not None else None
                except Exception:
                    end_line = None

        line_content = read_line_content(repo_path, file_path, line)

        # props/tags/cwe candidates
        res_props = res.get("properties") if isinstance(res.get("properties"), dict) else {}
        rule_props = (rule_def.get("properties") if isinstance(rule_def, dict) else {}) if isinstance(rule_def, dict) else {}
        vendor_entry = ctx.get("vendor_entry") if isinstance(ctx.get("vendor_entry"), dict) else {}

        tags = _extract_tags(rule_def, res)
        cwe_candidates = _extract_cwe_candidates(res_props, rule_props, vendor_entry, tags)

        cls = resolve_owasp_and_cwe(
            tags=tags,
            cwe_candidates=cwe_candidates,
            vendor_owasp_2021_codes=ctx.get("vendor_codes") or [],
            cwe_to_owasp_map=cwe_to_owasp_map,
        )

        finding_id = f"snyk:{rule_id or 'unknown'}:{file_path or 'unknown'}:{line or 0}"

        finding = {
            "metadata": per_finding_meta,
            "finding_id": finding_id,
            "cwe_id": cls["cwe_id"],
            "cwe_ids": cls["cwe_ids"],
            "vuln_class": rule_name,
            "owasp_top_10_2017": cls["owasp_top_10_2017"],
            "owasp_top_10_2021": cls["owasp_top_10_2021"],
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "file_path": file_path,
            "line_number": line,
            "end_line_number": end_line,
            "line_content": line_content,
            "vendor": {"raw_result": res},
        }
        findings.append(finding)

    normalized = {
        "schema_version": "1.1",
        "tool": "snyk",
        "tool_version": metadata.get("scanner_version"),
        "target_repo": target_repo,
        "scan": scan_info,
        "run_metadata": metadata,
        "findings": findings,
    }
    write_json(normalized_path, normalized)


def main() -> int:
    load_dotenv()
    args = parse_args()
    ensure_snyk_token()

    repo_path = clone_repo(args.repo_url)
    repo_name = repo_path.name

    # run output root is runs/snyk/<repo_name>/YYYYMMDDNN
    output_root = Path(args.output_root) / repo_name
    run_id, run_dir = create_run_dir(output_root)

    raw_results_path = run_dir / f"{repo_name}.json"
    normalized_path = run_dir / f"{repo_name}.normalized.json"
    metadata_path = run_dir / "metadata.json"

    exit_code, elapsed, command_str, snyk_stdout, snyk_stderr = run_snyk_scan(
        repo_path=repo_path,
        raw_results_path=raw_results_path,
        org=args.org,
        severity_threshold=args.severity_threshold,
    )

    metadata = build_run_metadata(
        repo_path=repo_path,
        repo_name=repo_name,
        repo_url=args.repo_url,
        run_id=run_id,
        exit_code=exit_code,
        elapsed=elapsed,
        command_str=command_str,
        stdout=snyk_stdout,
        stderr=snyk_stderr,
    )

    # Load mappings (best-effort)
    mappings_dir = Path(args.mappings_dir)
    if not mappings_dir.is_absolute():
        mappings_dir = ROOT_DIR / mappings_dir

    cwe_to_owasp_map = load_cwe_to_owasp_map(mappings_dir)
    snyk_rule_map = load_snyk_rule_to_owasp_2021_map(mappings_dir)
    snyk_rule_index = build_snyk_rule_index(snyk_rule_map)

    metadata.setdefault("mappings", {})
    metadata["mappings"].update(
        {
            "mappings_dir": str(mappings_dir),
            "cwe_to_owasp_loaded": bool(cwe_to_owasp_map),
            "snyk_rule_to_owasp_2021_loaded": bool(snyk_rule_map),
        }
    )

    write_json(metadata_path, metadata)
    print("📄 Metadata saved to:", metadata_path)

    normalize_snyk_results(
        repo_path=repo_path,
        raw_results_path=raw_results_path,
        metadata=metadata,
        normalized_path=normalized_path,
        cwe_to_owasp_map=cwe_to_owasp_map,
        snyk_rule_to_owasp_2021_map=snyk_rule_map,
        snyk_rule_index=snyk_rule_index,
    )

    print("📄 Normalized JSON saved to:", normalized_path)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
