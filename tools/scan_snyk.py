#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

from dotenv import load_dotenv

# Shared normalization helpers
from normalize_common import (
    write_json as write_json_common,
    build_target_repo,
    build_scan_info,
    build_per_finding_metadata,
    read_line_content,
)

# Load .env from project root (one level up from tools/)
ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")

# Shared helpers used across scan_* tools
from run_utils import (
    get_repo_name,
    clone_repo,
    get_git_commit,
    get_commit_author_info,
    create_run_dir,
)


# ---------------------------------------------------------------------------
# OWASP helper tables + parsing
# ---------------------------------------------------------------------------

# OWASP Top 10 2021 mapping (A01..A10 → human name)
OWASP_TOP_10_2021_NAMES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

# OWASP Top 10 2017 mapping (A1..A10 → human name)
OWASP_TOP_10_2017_NAMES = {
    "A1": "Injection",
    "A2": "Broken Authentication",
    "A3": "Sensitive Data Exposure",
    "A4": "XML External Entities (XXE)",
    "A5": "Broken Access Control",
    "A6": "Security Misconfiguration",
    "A7": "Cross-Site Scripting (XSS)",
    "A8": "Insecure Deserialization",
    "A9": "Using Components with Known Vulnerabilities",
    "A10": "Insufficient Logging & Monitoring",
}


_CWE_RE = re.compile(r"(?:^|[^a-z0-9])(cwe[-: ]?\d{1,6})(?:[^a-z0-9]|$)", re.IGNORECASE)
_CWE_NUM_RE = re.compile(r"cwe[-: ]?(\d{1,6})", re.IGNORECASE)
_OWASP_CODE_RE = re.compile(r"\b(a\d{1,2})\b", re.IGNORECASE)


def _normalize_cwe(value: str) -> str | None:
    """Return a canonical CWE like 'CWE-79' from messy inputs."""
    if not value:
        return None
    m = _CWE_NUM_RE.search(str(value))
    if not m:
        # Sometimes we get just "79" or similar
        digits = str(value).strip()
        if digits.isdigit():
            return f"CWE-{digits}"
        return None
    return f"CWE-{m.group(1)}"


def _normalize_owasp_code(code: str, year: str) -> str | None:
    """Normalize OWASP codes to:
    - 2021: A01..A10
    - 2017: A1..A10
    """
    if not code:
        return None
    c = str(code).strip().upper()
    if c.startswith("OWASP"):
        # Defensive: strip any prefix noise
        c = c.replace("OWASP", "").strip()

    # Pull out the numeric part
    if c.startswith("A"):
        num_str = c[1:]
    else:
        num_str = c
    if not num_str.isdigit():
        # Try to find Axx inside the string
        m = _OWASP_CODE_RE.search(c.lower())
        if not m:
            return None
        num_str = m.group(1)[1:]
    try:
        num = int(num_str)
    except ValueError:
        return None

    if num < 1 or num > 10:
        return None

    if year == "2021":
        return f"A{num:02d}"
    # 2017
    return f"A{num}"


def _build_owasp_block(codes: list[str], names: dict[str, str], year: str) -> dict | None:
    # De-dup while preserving order
    deduped = list(dict.fromkeys([c for c in codes if c]))
    if not deduped:
        return None
    categories: list[str] = []
    for c in deduped:
        categories.append(f"{c}:{year}-{names.get(c, 'Unknown')}")
    return {"codes": deduped, "categories": categories}


def _extract_tags(*candidates) -> list[str]:
    tags: list[str] = []
    for c in candidates:
        if not c:
            continue
        if isinstance(c, list):
            tags.extend([t for t in c if isinstance(t, str) and t.strip()])
        elif isinstance(c, str) and c.strip():
            tags.append(c.strip())
    return tags


def _extract_cwe_ids_from_props_and_tags(props: dict, tags: list[str]) -> list[str]:
    cwe_ids: list[str] = []

    # 1) Direct properties key(s)
    for key in ("cwe", "cwe_id", "cweId", "cwe_ids"):
        val = props.get(key)
        if not val:
            continue
        if isinstance(val, list):
            for item in val:
                c = _normalize_cwe(str(item))
                if c:
                    cwe_ids.append(c)
        else:
            c = _normalize_cwe(str(val))
            if c:
                cwe_ids.append(c)

    # 2) Parse tags like "CWE-79" or "cwe:79"
    for t in tags:
        m = _CWE_RE.search(t)
        if m:
            c = _normalize_cwe(m.group(1))
            if c:
                cwe_ids.append(c)

    # De-dup
    return list(dict.fromkeys(cwe_ids))


def _extract_owasp_codes_from_tags(tags: list[str], year: str) -> list[str]:
    """Extract OWASP Top 10 codes (A01..A10) from free-form tags.

    Important nuance:
      - Many vendors (including Snyk rule docs) express OWASP Top 10 (2021) as `OWASP:A03`
        **without** explicitly mentioning the year.
      - We therefore treat generic `OWASP:*` tags as **2021** by default.
      - For 2017, we only accept tags that explicitly mention `2017` to avoid misclassification.
    """
    codes: list[str] = []
    for t in tags:
        if not isinstance(t, str):
            continue
        low = t.lower()

        if year == "2021":
            # Accept:
            #   - explicit 2021 mentions
            #   - generic OWASP/top10 mentions (common in vendor tags/docs)
            # Reject:
            #   - explicit 2017 mentions
            if "2017" in low:
                continue
            if ("2021" not in low) and ("owasp" not in low) and ("top10" not in low) and ("top 10" not in low):
                continue

        elif year == "2017":
            # Be strict: only accept tags explicitly mentioning 2017
            if "2017" not in low:
                continue

        m = _OWASP_CODE_RE.search(low)
        if not m:
            continue
        code = _normalize_owasp_code(m.group(1), year=year)
        if code:
            codes.append(code)

    return list(dict.fromkeys(codes))


def _load_cwe_to_owasp_mapping(root_dir: Path) -> dict[str, dict]:
    """Load a local CWE→OWASP mapping file (optional).

    We keep this local (checked into the repo) so normalization doesn't depend on
    a network call / scraping vendor docs.

    Expected file shape (generated by our project):
      { "cwe_to_owasp": { "CWE-79": { "owasp_top_10_2021": {...}, ... } } }
    """
    candidate_paths = [
        root_dir / "mappings" / "cwe_to_owasp_top10_mitre.json",
        root_dir / "cwe_to_owasp_top10_mitre.json",
        root_dir / "tools" / "cwe_to_owasp_top10_mitre.json",
    ]

    for p in candidate_paths:
        if not p.exists():
            continue
        try:
            with p.open("r", encoding="utf-8") as f:
                data = json.load(f)
            mapping = (data or {}).get("cwe_to_owasp") or {}
            if isinstance(mapping, dict):
                return mapping
        except Exception:
            # Best-effort: if mapping can't be read, keep going without enrichment.
            pass

    return {}


def _load_snyk_rule_to_owasp_mapping(root_dir: Path) -> dict:
    """Load vendor rule→OWASP mapping derived from Snyk docs (optional).

    Expected file: mappings/snyk_rule_to_owasp_2021.json
    """
    candidates = [
        root_dir / "mappings" / "snyk_rule_to_owasp_2021.json",
        root_dir / "snyk_rule_to_owasp_2021.json",
    ]
    for p in candidates:
        try:
            if p.exists():
                with p.open(encoding="utf-8") as f:
                    return json.load(f) or {}
        except Exception:
            # Best-effort: if the mapping can't be read, just skip it.
            continue
    return {}


def _norm_rule_name(s: Optional[str]) -> str:
    """Normalize a rule name for resilient lookups."""
    if not s:
        return ""
    return re.sub(r"\s+", " ", s.strip()).lower()


def _build_snyk_rule_index(vendor_map: dict) -> dict[str, dict[str, dict]]:
    """Build an index for fast lookups: {lang: {normalized_rule_name: entry}}."""
    index: dict[str, dict[str, dict]] = {}
    languages = vendor_map.get("languages") if isinstance(vendor_map, dict) else None
    if not isinstance(languages, dict):
        return index

    for lang, rules in languages.items():
        if not isinstance(lang, str) or not isinstance(rules, dict):
            continue
        index[lang] = {}
        for rule_name, entry in rules.items():
            if not isinstance(rule_name, str) or not isinstance(entry, dict):
                continue
            index[lang][_norm_rule_name(rule_name)] = entry
    return index


def _lookup_snyk_vendor_owasp_2021(
    vendor_map: dict,
    vendor_index: dict[str, dict[str, dict]],
    language: Optional[str],
    rule_name: Optional[str],
) -> tuple[Optional[list[str]], Optional[dict]]:
    """Lookup vendor OWASP Top 10 2021 codes for a given Snyk rule.

    Returns:
      (codes, entry) where:
        - codes is a list (possibly empty) if a rule match exists,
          or None if the rule is not present in the vendor map.
        - entry is the mapping entry (or None).
    """
    if not vendor_map or not rule_name:
        return None, None

    lang = (language or "").lower()
    aliases = vendor_map.get("aliases") if isinstance(vendor_map, dict) else None
    if isinstance(aliases, dict) and lang in aliases:
        lang = aliases.get(lang) or lang

    entry = (vendor_index.get(lang) or {}).get(_norm_rule_name(rule_name))
    if entry is None:
        return None, None

    codes = entry.get("owasp_top_10_2021")
    if codes is None:
        codes = []
    # ensure list[str]
    return [str(c) for c in codes], entry

def _derive_owasp_blocks_from_cwe_ids(
    cwe_ids: list[str], cwe_to_owasp: dict[str, dict]
) -> Tuple[dict | None, dict | None]:
    """Derive OWASP blocks using a CWE→OWASP mapping (best-effort)."""
    if not cwe_ids or not cwe_to_owasp:
        return None, None

    codes_2017: list[str] = []
    codes_2021: list[str] = []

    for cwe in cwe_ids:
        entry = cwe_to_owasp.get(cwe)
        if not entry:
            continue

        o17 = (entry.get("owasp_top_10_2017") or {}).get("codes") or []
        o21 = (entry.get("owasp_top_10_2021") or {}).get("codes") or []
        if isinstance(o17, list):
            codes_2017.extend([str(x) for x in o17])
        if isinstance(o21, list):
            codes_2021.extend([str(x) for x in o21])

    # Normalize codes to our schema format
    norm_2017 = [
        _normalize_owasp_code(c, year="2017") for c in codes_2017 if isinstance(c, str)
    ]
    norm_2021 = [
        _normalize_owasp_code(c, year="2021") for c in codes_2021 if isinstance(c, str)
    ]

    block_2017 = _build_owasp_block(
        [c for c in norm_2017 if c], OWASP_TOP_10_2017_NAMES, year="2017"
    )
    block_2021 = _build_owasp_block(
        [c for c in norm_2021 if c], OWASP_TOP_10_2021_NAMES, year="2021"
    )
    return block_2017, block_2021
def parse_args() -> argparse.Namespace:
    """CLI arguments for running Snyk Code on a repo."""
    p = argparse.ArgumentParser(
        description="Run Snyk Code on a repo and save JSON + metadata."
    )
    p.add_argument(
        "--repo-url",
        help=(
            "Git URL of the repo to scan "
            "(e.g. https://github.com/juice-shop/juice-shop.git)"
        ),
    )
    p.add_argument(
        "--output-root",
        default="runs/snyk",
        help="Root folder to store outputs (default: runs/snyk)",
    )
    p.add_argument(
        "--org",
        default=None,
        help="Optional Snyk org id/slug to use with --org.",
    )
    p.add_argument(
        "--severity-threshold",
        default=None,
        choices=["low", "medium", "high"],
        help="Optional Snyk severity threshold (low|medium|high).",
    )
    args = p.parse_args()
    if not args.repo_url:
        args.repo_url = input("Enter Git repo URL to scan: ").strip()
    return args


def ensure_snyk_token() -> None:
    """Exit with an error message if SNYK_TOKEN is not set."""
    snyk_token = os.getenv("SNYK_TOKEN")
    if not snyk_token:
        print(
            "ERROR: SNYK_TOKEN is not set.\n"
            "Add it to your .env or export it in your shell before running.",
            file=sys.stderr,
        )
        sys.exit(1)


def get_snyk_version() -> str:
    """Return the installed Snyk CLI version, or 'unknown' if it fails."""
    try:
        out = subprocess.check_output(["snyk", "--version"], text=True)
        return out.strip()
    except Exception:
        return "unknown"


def run_snyk_scan(
    repo_path: Path,
    repo_name: str,
    raw_results_path: Path,
    org: Optional[str],
    severity_threshold: Optional[str],
) -> Tuple[int, float, str]:
    """
    Run 'snyk code test' and return (exit_code, elapsed_seconds, command_string).
    """
    cmd = ["snyk", "code", "test", "--json-file-output", str(raw_results_path)]
    if org:
        cmd.extend(["--org", org])
    if severity_threshold:
        cmd.extend(["--severity-threshold", severity_threshold])

    print(f"\n🔍 Running Snyk Code on {repo_name} ...")
    print("Command:", " ".join(cmd))

    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            cwd=repo_path,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError:
        print(
            "ERROR: 'snyk' CLI not found on PATH. "
            "Install it with 'npm install -g snyk' and make sure 'snyk --version' works.",
            file=sys.stderr,
        )
        sys.exit(1)
    elapsed = time.time() - t0

    # Exit codes: 0 = no vulns, 1 = vulns found, 2/3 = failure
    if proc.returncode in (0, 1):
        print(
            f"✅ Snyk Code finished in {elapsed:.2f}s "
            f"(exit code {proc.returncode})"
        )
    else:
        print(f"⚠️ Snyk Code failed with exit code {proc.returncode}")
        print(proc.stderr[:2000])

    return proc.returncode, elapsed, " ".join(cmd)


def build_run_metadata(
    repo_path: Path,
    repo_name: str,
    repo_url: str,
    run_id: str,
    exit_code: int,
    elapsed: float,
    command_str: str,
) -> dict:
    """Collect commit + scanner info into a single metadata dict."""
    commit = get_git_commit(repo_path)
    author_info = get_commit_author_info(repo_path, commit)
    scanner_version = get_snyk_version()

    return {
        "scanner": "snyk",
        "scanner_version": scanner_version,
        "repo_name": repo_name,
        "repo_url": repo_url,
        "repo_commit": commit,
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(),
        "command": command_str,
        "scan_time_seconds": elapsed,
        "exit_code": exit_code,
        **author_info,
    }


def write_json(path: Path, data: dict) -> None:
    """Write a JSON file with pretty-printing."""
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)



def normalize_snyk_results(
    *,
    repo_path: Path,
    raw_results_path: Path,
    metadata: dict,
    normalized_path: Path,
    cwe_to_owasp: dict[str, dict],
    snyk_rule_to_owasp: dict[str, dict],
    snyk_rule_to_owasp_index: dict[tuple[str, str], dict],
) -> None:
    """Normalize Snyk Code SARIF-ish JSON into our schema v1.1.

    Key goals:
      - Keep output schema consistent with other tools (reuse normalize_common).
      - Populate CWE/OWASP when possible using:
          1) tags in SARIF output
          2) offline vendor rule mapping (Snyk docs snapshot)
          3) offline CWE→OWASP mapping (MITRE snapshot), with guardrails
      - Avoid spaghetti by caching rule-level enrichment (vendor lookups) once per rule.
    """
    # Stable header blocks for normalized schema
    target_repo = build_target_repo(metadata)
    scan_info = build_scan_info(metadata, raw_results_path)

    # If raw JSON is missing, still emit a valid normalized doc
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
        write_json_common(normalized_path, normalized)
        return

    with raw_results_path.open("r", encoding="utf-8") as f:
        raw = json.load(f)

    runs = raw.get("runs") or []
    if not runs:
        normalized = {
            "schema_version": "1.1",
            "tool": "snyk",
            "tool_version": metadata.get("scanner_version"),
            "target_repo": target_repo,
            "scan": scan_info,
            "run_metadata": metadata,
            "findings": [],
        }
        write_json_common(normalized_path, normalized)
        return

    # The CLI typically returns a single SARIF run
    run0 = runs[0] if isinstance(runs[0], dict) else {}
    driver = (((run0.get("tool") or {}).get("driver")) or {}) if isinstance(run0, dict) else {}
    rules = driver.get("rules") or []
    results = run0.get("results") or []

    # Build a rule lookup by ID for quick access
    rules_by_id: dict[str, dict] = {}
    if isinstance(rules, list):
        for r in rules:
            if not isinstance(r, dict):
                continue
            rid = r.get("id")
            if isinstance(rid, str) and rid:
                rules_by_id[rid] = r

    # Cache rule-level context so we don't redo vendor mapping work per finding
    rule_ctx_cache: dict[str, dict] = {}

    def _get_rule_ctx(rule_id: Optional[str], rule_def: Optional[dict]) -> dict:
        cache_key = rule_id or ""
        if cache_key in rule_ctx_cache:
            return rule_ctx_cache[cache_key]

        # Prefer the Snyk docs "Rule Name" (usually rule.shortDescription.text in SARIF).
        rule_name = None
        if isinstance(rule_def, dict):
            rule_name = (rule_def.get("shortDescription") or {}).get("text") or rule_def.get("name")

        # Heuristic: Snyk rule_id often looks like "<language>/<rule>".
        language = None
        if isinstance(rule_id, str) and "/" in rule_id:
            language = rule_id.split("/", 1)[0]
        elif isinstance(rule_id, str):
            language = rule_id

        vendor_codes, _vendor_entry = _lookup_snyk_vendor_owasp_2021(
            snyk_rule_to_owasp,
            snyk_rule_to_owasp_index,
            language,
            rule_name,
        )

        ctx = {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "language": language,
            "vendor_owasp2021_codes": vendor_codes,
            "vendor_present": bool(vendor_codes),
        }
        rule_ctx_cache[cache_key] = ctx
        return ctx

    def _resolve_classification(*, combined_props: dict, tags: list[str], rule_ctx: dict) -> dict:
        """Resolve CWE + OWASP (2017/2021) blocks with the same precedence policy used today."""
        cwe_ids = _extract_cwe_ids_from_props_and_tags(combined_props, tags)
        cwe_id = cwe_ids[0] if cwe_ids else None

        # 1) From tags (best if explicitly present)
        owasp2017_codes = _extract_owasp_codes_from_tags(tags, year="2017")
        owasp2021_codes = _extract_owasp_codes_from_tags(tags, year="2021")

        owasp_2017_block = _build_owasp_block(owasp2017_codes, OWASP_TOP_10_2017_NAMES, year="2017")
        owasp_2021_block = _build_owasp_block(owasp2021_codes, OWASP_TOP_10_2021_NAMES, year="2021")

        # 2) Vendor offline mapping (Snyk docs) for OWASP 2021
        if owasp_2021_block is None and rule_ctx.get("vendor_present"):
            owasp_2021_block = _build_owasp_block(
                rule_ctx.get("vendor_owasp2021_codes") or [],
                OWASP_TOP_10_2021_NAMES,
                year="2021",
            )

        # 3) CWE→OWASP fallback mapping (offline)
        if cwe_to_owasp:
            derived_2017, derived_2021 = _derive_owasp_blocks_from_cwe_ids(cwe_ids, cwe_to_owasp)

            if owasp_2017_block is None:
                owasp_2017_block = derived_2017

            # Guardrail: only derive 2021 from CWE when:
            # - tags did not give us a 2021 code, AND
            # - there is no vendor mapping for the rule (avoid overriding vendor truth)
            if owasp_2021_block is None and (not owasp2021_codes) and (not rule_ctx.get("vendor_present")):
                owasp_2021_block = derived_2021

        # This repo currently uses "vuln_class" as a best-effort category string.
        vuln_class = rule_ctx.get("rule_name") or None

        return {
            "cwe_id": cwe_id,
            "cwe_ids": cwe_ids,
            "vuln_class": vuln_class,
            "owasp_top_10_2017": owasp_2017_block,
            "owasp_top_10_2021": owasp_2021_block,
        }

    findings: list[dict] = []

    if not isinstance(results, list):
        results = []

    for res in results:
        if not isinstance(res, dict):
            continue

        # --- Basic fields ---
        rule_id = res.get("ruleId")
        rule_id = rule_id if isinstance(rule_id, str) else None
        rule_def = rules_by_id.get(rule_id) if rule_id else None

        # Severity: prefer SARIF level (error/warning/note), then fallback to "warning"
        severity = "medium"
        level = res.get("level")
        if isinstance(level, str):
            if level == "error":
                severity = "high"
            elif level == "warning":
                severity = "medium"
            elif level == "note":
                severity = "low"

        message = None
        msg_obj = res.get("message")
        if isinstance(msg_obj, dict):
            message = msg_obj.get("text")
        if not message and isinstance(rule_def, dict):
            message = ((rule_def.get("shortDescription") or {}).get("text")) or ((rule_def.get("fullDescription") or {}).get("text"))
        if not message:
            message = "Snyk finding"

        # --- Location ---
        file_path = None
        line = None
        end_line = None

        locations = res.get("locations")
        if isinstance(locations, list) and locations:
            loc0 = locations[0] if isinstance(locations[0], dict) else {}
            phys = (loc0.get("physicalLocation") or {}) if isinstance(loc0, dict) else {}
            artifact = (phys.get("artifactLocation") or {}) if isinstance(phys, dict) else {}
            file_path = artifact.get("uri") if isinstance(artifact, dict) else None

            region = (phys.get("region") or {}) if isinstance(phys, dict) else {}
            if isinstance(region, dict):
                line = region.get("startLine")
                end_line = region.get("endLine")

        line = int(line) if isinstance(line, int) else (int(line) if isinstance(line, str) and line.isdigit() else None)
        end_line = int(end_line) if isinstance(end_line, int) else (int(end_line) if isinstance(end_line, str) and end_line.isdigit() else None)

        line_content = read_line_content(repo_path, file_path, line)

        # --- Props & tags (for classification) ---
        res_props = res.get("properties") if isinstance(res.get("properties"), dict) else {}
        rule_props = rule_def.get("properties") if isinstance(rule_def, dict) and isinstance(rule_def.get("properties"), dict) else {}

        combined_props: dict = {}
        combined_props.update(rule_props)
        combined_props.update(res_props)

        tags = _extract_tags(combined_props)

        # --- Rule-level cached context ---
        rule_ctx = _get_rule_ctx(rule_id, rule_def)
        cls = _resolve_classification(combined_props=combined_props, tags=tags, rule_ctx=rule_ctx)

        # Consistent per-finding metadata
        per_finding_metadata = build_per_finding_metadata(
            tool="snyk",
            tool_version=metadata.get("scanner_version"),
            target_repo=target_repo,
            scan_info=scan_info,
        )

        finding = {
            "metadata": per_finding_metadata,
            "finding_id": f"snyk:{rule_id}:{file_path}:{line}",
            "cwe_id": cls["cwe_id"],
            "cwe_ids": cls["cwe_ids"],
            "vuln_class": cls["vuln_class"],
            "owasp_top_10_2017": cls["owasp_top_10_2017"],
            "owasp_top_10_2021": cls["owasp_top_10_2021"],
            "rule_id": rule_id,
            "title": message,
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
    write_json_common(normalized_path, normalized)
def main() -> None:
    args = parse_args()
    ensure_snyk_token()

    # 1. Clone repo (shared helpers)
    repo_base = Path("repos")
    repo_path = clone_repo(args.repo_url, repo_base)
    repo_name = get_repo_name(args.repo_url)

    # 2. Prepare output paths (group by repo name)
    #    This creates: ROOT/runs/snyk/<repo_name>/<run_id>/
    output_root = Path(args.output_root) / repo_name
    created = create_run_dir(output_root)

    # create_run_dir contract differs across versions:
    # - may return Path
    # - may return (run_id, Path)
    # - may return (Path, run_id)
    if isinstance(created, tuple):
        # Prefer the Path-like element as run_dir
        path_elem = next((x for x in created if isinstance(x, Path)), None)
        run_dir = path_elem if path_elem is not None else Path(created[0])
        # Prefer a string run_id if present; otherwise fall back to directory name
        run_id_elem = next((x for x in created if isinstance(x, str)), None)
        run_id = run_id_elem if run_id_elem is not None else run_dir.name
    else:
        run_dir = created
        run_id = run_dir.name

    # Important: use absolute path so Snyk writes to the pipeline folder,
    # not inside repos/<repo_name> when cwd=repo_path
    run_dir = Path(run_dir).resolve()
    raw_results_path = run_dir / f"{repo_name}.json"
    normalized_path = run_dir / f"{repo_name}.normalized.json"
    metadata_path = run_dir / "metadata.json"

    # 3. Run Snyk scan
    exit_code, elapsed, command_str = run_snyk_scan(
        repo_path=repo_path,
        repo_name=repo_name,
        raw_results_path=raw_results_path,
        org=args.org,
        severity_threshold=args.severity_threshold,
    )
    print("Raw JSON path (expected):", raw_results_path)

    # 4. Build and save metadata
    metadata = build_run_metadata(
        repo_path=repo_path,
        repo_name=repo_name,
        repo_url=args.repo_url,
        run_id=run_id,
        exit_code=exit_code,
        elapsed=elapsed,
        command_str=command_str,
    )
    write_json(metadata_path, metadata)
    print("📄 Metadata saved to:", metadata_path)

    # 5. Load offline mappings (optional)
    cwe_to_owasp = _load_cwe_to_owasp_mapping(ROOT_DIR)
    snyk_rule_to_owasp = _load_snyk_rule_to_owasp_mapping(ROOT_DIR)
    snyk_rule_to_owasp_index = _build_snyk_rule_index(snyk_rule_to_owasp)

    metadata.setdefault("mappings", {})
    metadata["mappings"].update({
        "cwe_to_owasp_loaded": bool(cwe_to_owasp),
        "snyk_rule_to_owasp_loaded": bool(snyk_rule_to_owasp),
    })

    # 5. Normalized JSON
    normalize_snyk_results(
        repo_path=repo_path,
        raw_results_path=raw_results_path,
        metadata=metadata,
        normalized_path=normalized_path,
        cwe_to_owasp=cwe_to_owasp,
        snyk_rule_to_owasp=snyk_rule_to_owasp,
        snyk_rule_to_owasp_index=snyk_rule_to_owasp_index,
    )
    print("📄 Normalized JSON saved to:", normalized_path)


if __name__ == "__main__":
    main()
