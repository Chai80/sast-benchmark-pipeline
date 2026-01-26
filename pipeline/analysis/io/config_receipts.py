from __future__ import annotations

"""pipeline.analysis.io.config_receipts

Helpers for treating scanner configuration as a first-class, comparable input.

Context
-------
Scanner findings are not purely a function of "the tool". They also depend on
configuration (enabled rules, policies, profiles, etc.).

The execution layer writes a lightweight, tool-agnostic receipt file:

  cases/<case_id>/tool_runs/<tool>/.../config_receipt.json

This module provides:
- deterministic discovery of those receipts
- a *stable* config signature hash (ignoring run-specific timestamps)
- a small suite-level summary for manifests / compare reports

Design constraints
------------------
- Analysis-only: read existing files; do not run tools.
- Small + stable outputs: suitable for suite.json and qa_manifest.json.
- Deterministic: stable ordering and hashing.

NOTE
----
The config signature hash is intentionally conservative: it only includes
fields that are expected to be stable across cases in the same profile.
It should evolve as scanners export richer config inventories.
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence


def _json_dumps_canonical(obj: Any) -> str:
    """Deterministic JSON encoding suitable for hashing."""

    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return int(default)
        if isinstance(x, bool):
            return int(x)
        return int(float(str(x).strip()))
    except Exception:
        return int(default)


def load_json_dict(path: Path) -> Optional[Dict[str, Any]]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else None
    except Exception:
        return None


def discover_config_receipt_paths(suite_dir: Path) -> List[Path]:
    """Deterministically discover config_receipt.json files under a suite."""

    suite_dir = Path(suite_dir).resolve()
    cases_dir = suite_dir / "cases"
    if not cases_dir.exists() or not cases_dir.is_dir():
        return []

    # Layout v2: cases/<case>/tool_runs/<tool>/<run_id>/config_receipt.json
    # Layout v1: cases/<case>/tool_runs/<tool>/<repo>/<run_id>/config_receipt.json
    found: List[Path] = []
    for p in cases_dir.glob("*/tool_runs/*/**/config_receipt.json"):
        try:
            if p.exists() and p.is_file():
                found.append(p.resolve())
        except Exception:
            continue

    # De-dupe + stable sort.
    uniq = sorted(set(found), key=lambda x: str(x))
    return list(uniq)


def stable_config_signature(receipt: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a stable subset of config_receipt.json suitable for hashing.

    We intentionally ignore per-run volatile fields such as:
    - recorded_at / started / finished
    - exit_code
    - command (often includes run-specific output paths)

    The goal is to capture "config intent" rather than run metadata.
    """

    artifacts = (
        receipt.get("artifacts")
        if isinstance(receipt.get("artifacts"), Mapping)
        else {}
    )

    return {
        "schema_version": _safe_int(receipt.get("schema_version"), 0),
        "tool": str(receipt.get("tool") or "").strip(),
        "profile": str(receipt.get("profile") or "").strip(),
        "artifacts": {
            # If a run exports a rules inventory (CSV/PDF/etc), include the relative
            # path so suites can be compared when inventories change.
            "rules_inventory": (
                artifacts.get("rules_inventory")
                if isinstance(artifacts, Mapping)
                else None
            ),
        },
    }


def config_signature_hash(receipt: Mapping[str, Any]) -> str:
    """Compute a stable sha256 hash of :func:`stable_config_signature`."""

    sig = stable_config_signature(receipt)
    return sha256_text(_json_dumps_canonical(sig))


def _normalize_hash_map(raw: Any) -> Dict[str, List[str]]:
    """Normalize config_receipt_hashes to tool -> sorted unique list of hashes."""

    out: Dict[str, List[str]] = {}

    if not isinstance(raw, Mapping):
        return out

    for tool, v in raw.items():
        t = str(tool or "").strip()
        if not t:
            continue

        hashes: List[str] = []
        if isinstance(v, str):
            if v.strip():
                hashes = [v.strip()]
        elif isinstance(v, list):
            hashes = [str(x).strip() for x in v if str(x).strip()]
        else:
            # Unknown shape; store a stringified value as a last resort.
            sv = str(v).strip()
            if sv:
                hashes = [sv]

        # Unique + stable order.
        uniq = sorted(set(hashes))
        if uniq:
            out[t] = uniq

    return out


def normalize_scanner_config(obj: Mapping[str, Any]) -> Dict[str, Any]:
    """Best-effort normalize scanner_config payload from suite.json / qa_manifest."""

    profile = obj.get("profile") if isinstance(obj, Mapping) else None
    profile_s = str(profile).strip() if profile is not None else ""
    profile_mode = str(obj.get("profile_mode") or "").strip()

    hashes = _normalize_hash_map(obj.get("config_receipt_hashes"))

    tools_seen: List[str] = []
    raw_tools = obj.get("tools_seen")
    if isinstance(raw_tools, list):
        tools_seen = sorted(set([str(x).strip() for x in raw_tools if str(x).strip()]))
    elif hashes:
        tools_seen = sorted(hashes.keys())

    missing_tools: List[str] = []
    raw_missing = obj.get("missing_tools")
    if isinstance(raw_missing, list):
        missing_tools = sorted(
            set([str(x).strip() for x in raw_missing if str(x).strip()])
        )

    warnings: List[str] = []
    raw_warn = obj.get("warnings")
    if isinstance(raw_warn, list):
        warnings = [str(x) for x in raw_warn if str(x).strip()]

    receipts_found = _safe_int(obj.get("receipts_found"), 0)

    out: Dict[str, Any] = {
        "profile": profile_s or None,
        "profile_mode": profile_mode or None,
        "config_receipt_hashes": hashes,
        "receipts_found": int(receipts_found),
        "tools_seen": tools_seen,
        "missing_tools": missing_tools,
        "warnings": warnings,
    }

    # Backfill mode from profile/hashes when not provided.
    if out.get("profile_mode") is None:
        if out.get("profile") is None:
            out["profile_mode"] = "unknown"
        else:
            out["profile_mode"] = "uniform"

    return out


def extract_scanner_config_from_manifest(
    manifest: Optional[Mapping[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not isinstance(manifest, Mapping):
        return None
    inputs = manifest.get("inputs")
    if not isinstance(inputs, Mapping):
        return None
    sc = inputs.get("scanner_config")
    if not isinstance(sc, Mapping):
        return None
    return normalize_scanner_config(sc)


def extract_scanner_config_from_suite_json(
    suite_json: Optional[Mapping[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not isinstance(suite_json, Mapping):
        return None
    plan = suite_json.get("plan")
    if not isinstance(plan, Mapping):
        return None
    sc = plan.get("scanner_config")
    if not isinstance(sc, Mapping):
        return None
    return normalize_scanner_config(sc)


def summarize_scanner_config(
    suite_dir: Path,
    *,
    scanners: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Summarize config receipts for a suite.

    Returns a small dict intended to be embedded into suite.json and qa_manifest.json.
    """

    suite_dir = Path(suite_dir).resolve()

    receipt_paths = discover_config_receipt_paths(suite_dir)

    hashes_by_tool: Dict[str, List[str]] = {}
    profile_values: List[str] = []

    warnings: List[str] = []

    # Build per-tool unique hash lists.
    tmp: Dict[str, set[str]] = {}

    for p in receipt_paths:
        rec = load_json_dict(p)
        if not isinstance(rec, dict):
            continue

        tool = str(rec.get("tool") or "").strip()
        if not tool:
            # Best-effort fallback: infer tool name from path segment after tool_runs/
            try:
                parts = p.parts
                if "tool_runs" in parts:
                    idx = parts.index("tool_runs")
                    tool = str(parts[idx + 1]).strip() if idx + 1 < len(parts) else ""
            except Exception:
                tool = ""

        if not tool:
            continue

        prof = str(rec.get("profile") or "").strip()
        if prof:
            profile_values.append(prof)

        try:
            h = config_signature_hash(rec)
        except Exception:
            continue

        tmp.setdefault(tool, set()).add(h)

    for tool, hs in tmp.items():
        hashes_by_tool[tool] = sorted(set(hs))

    # Profile mode summary.
    uniq_profiles = sorted(set([p for p in profile_values if p]))
    if len(uniq_profiles) == 1:
        profile: Optional[str] = uniq_profiles[0]
        profile_mode = "uniform"
    elif len(uniq_profiles) == 0:
        profile = None
        profile_mode = "unknown"
    else:
        profile = "mixed"
        profile_mode = "mixed"
        warnings.append(f"multiple profiles observed: {uniq_profiles}")

    tools_seen = sorted(hashes_by_tool.keys())

    expected = sorted(set([str(s).strip() for s in (scanners or []) if str(s).strip()]))
    missing_tools = [t for t in expected if t not in hashes_by_tool]
    if missing_tools:
        warnings.append(f"missing config_receipt for tools: {missing_tools}")

    multi_sig_tools = sorted([t for t, hs in hashes_by_tool.items() if len(hs) > 1])
    if multi_sig_tools:
        warnings.append(
            f"multiple config signatures detected for tools: {multi_sig_tools}"
        )

    return {
        "profile": profile,
        "profile_mode": profile_mode,
        "config_receipt_hashes": {
            t: hashes_by_tool[t] for t in sorted(hashes_by_tool.keys())
        },
        "receipts_found": int(len(receipt_paths)),
        "tools_seen": tools_seen,
        "missing_tools": missing_tools,
        "warnings": warnings,
    }


def load_scanner_config(
    suite_dir: Path,
    *,
    qa_manifest: Optional[Mapping[str, Any]] = None,
    suite_json: Optional[Mapping[str, Any]] = None,
    scanners: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Load a scanner_config record from canonical artifacts when available.

    Precedence:
    1) qa_manifest.json (if present)
    2) suite.json (if present)
    3) derive by scanning config_receipt.json files

    Returns a normalized dict.
    """

    m = extract_scanner_config_from_manifest(qa_manifest)
    if m is not None:
        return dict(m)

    s = extract_scanner_config_from_suite_json(suite_json)
    if s is not None:
        return dict(s)

    return normalize_scanner_config(
        summarize_scanner_config(suite_dir, scanners=scanners)
    )
