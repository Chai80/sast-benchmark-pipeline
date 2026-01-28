"""tools/core_normalize.py

Shared normalization helpers.

Normalizers are allowed to be "thin" and focused on parsing tool output.
These helpers provide deterministic ordering and small path utilities so
benchmark runs can be meaningfully diffed.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from sast_benchmark.domain.finding import FindingNormalized


def normalize_repo_relative_path(repo_path: Path, tool_path: Optional[str]) -> Optional[str]:
    """Convert tool-reported absolute paths to repo-relative if possible."""
    if not tool_path:
        return None
    p = Path(tool_path)
    try:
        if p.is_absolute():
            return str(p.resolve().relative_to(repo_path.resolve()))
    except Exception:
        return tool_path
    return tool_path


def finalize_normalized_findings(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Make normalized findings deterministic.

    Normalizers are allowed to be "thin" and focused on parsing, but the
    benchmark pipeline benefits enormously from stable ordering so runs can be
    diffed meaningfully.

    This helper:
      - sorts set-like list fields (e.g., cwe_ids)
      - sorts OWASP block codes/categories
      - sorts the overall findings list by a stable key

    It mutates dictionaries in-place (for efficiency) and returns the sorted
    list.
    """
    # Optional lightweight schema validation (non-fatal by default).
    # Enable with: SAST_VALIDATE_NORMALIZED=1
    validate = os.environ.get("SAST_VALIDATE_NORMALIZED", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
    }
    strict = os.environ.get("SAST_VALIDATE_NORMALIZED_STRICT", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
    }
    validation_errors: List[str] = []

    def _safe_int(x: Any) -> int:
        try:
            if x is None:
                return -1
            return int(x)
        except Exception:
            return -1

    def _sort_list_field(f: Dict[str, Any], key: str) -> None:
        v = f.get(key)
        if isinstance(v, list):
            # Treat as set-like: sort for stability.
            f[key] = sorted([str(x) for x in v if x is not None])

    def _sort_owasp_block(f: Dict[str, Any], key: str) -> None:
        block = f.get(key)
        if not isinstance(block, dict):
            return
        codes = block.get("codes")
        cats = block.get("categories")
        if isinstance(codes, list):
            block["codes"] = sorted([str(x) for x in codes if x is not None])
        if isinstance(cats, list):
            block["categories"] = sorted([str(x) for x in cats if x is not None])

    cleaned: List[Dict[str, Any]] = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue

        if validate:
            problems = FindingNormalized.validate_dict(f)
            if problems:
                where = f"{f.get('file_path') or '<no-file>'}:{f.get('line_number') or '?'}"
                validation_errors.append(
                    f"normalized finding invalid at {where} (finding_id={f.get('finding_id')!r}): {', '.join(problems)}"
                )

        _sort_list_field(f, "cwe_ids")

        # OWASP blocks (compat + explicit vendor/canonical views)
        for k in (
            "owasp_top_10_2017",
            "owasp_top_10_2021",
            "owasp_top_10_2017_vendor",
            "owasp_top_10_2017_canonical",
            "owasp_top_10_2021_vendor",
            "owasp_top_10_2021_canonical",
        ):
            _sort_owasp_block(f, k)

        cleaned.append(f)

    if validate and validation_errors:
        head = validation_errors[:25]
        msg = "\n".join(
            ["[WARN] Normalized finding schema issues detected:"]
            + [f"  - {x}" for x in head]
        )
        if len(validation_errors) > 25:
            msg += f"\n  ... ({len(validation_errors) - 25} more)"
        print(msg, file=sys.stderr)
        if strict:
            raise ValueError(
                f"Normalized findings failed validation ({len(validation_errors)} issues)."
            )

    def _key(f: Dict[str, Any]) -> tuple:
        return (
            str(f.get("file_path") or ""),
            _safe_int(f.get("line_number")),
            _safe_int(f.get("end_line_number")),
            str(f.get("rule_id") or ""),
            str(f.get("title") or ""),
            str(f.get("finding_id") or ""),
        )

    cleaned.sort(key=_key)
    return cleaned
