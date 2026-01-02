"""pipeline.analysis.location_signatures

Shared helpers for location-based hotspot alignment.

This module is intentionally dependency-light:
- No scanner-specific logic
- No CWE/OWASP mapping
- Only uses normalized finding fields that should exist across tools

Why this exists
---------------
Once you introduce location-based alignment, you'll need the same path + line
bucketing logic in multiple places (matrix generation, drilldown exporters,
metrics). Putting it in one place prevents signature drift and spaghetti.

Signature format
----------------
We keep signatures readable and stable for spreadsheets and folder names.

    <normalized_file_path>|L<bucket_start>-<bucket_end>

Where bucket_start/bucket_end are 1-indexed line numbers.

Example:
    routes/search.ts|L21-30
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple

from pipeline.analysis.path_normalization import normalize_file_path


@dataclass(frozen=True)
class LineBucket:
    start: int
    end: int

    def label(self) -> str:
        return f"L{self.start}-{self.end}"


@dataclass(frozen=True)
class LocationSignature:
    file: str
    bucket: LineBucket

    def id(self) -> str:
        return f"{self.file}|{self.bucket.label()}"


def _to_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        i = int(v)
    except Exception:
        return None
    return i


def anchor_line(finding: Mapping[str, Any]) -> Optional[int]:
    """Pick a single 'anchor line' for a finding.

    We default to line_number and fall back to end_line_number.

    Notes
    -----
    Different tools choose different anchors (start, end, secondary location).
    This helper keeps the choice consistent within this pipeline.
    """

    ln = _to_int(finding.get("line_number"))
    if ln and ln > 0:
        return ln
    eln = _to_int(finding.get("end_line_number"))
    if eln and eln > 0:
        return eln
    return None


def bucket_for_line(line: int, bucket_size: int) -> Optional[LineBucket]:
    """Convert a 1-indexed line number into a fixed-size bucket."""
    if not isinstance(bucket_size, int) or bucket_size <= 0:
        raise ValueError(f"bucket_size must be a positive int, got: {bucket_size!r}")
    if line <= 0:
        return None
    start = ((line - 1) // bucket_size) * bucket_size + 1
    end = start + bucket_size - 1
    return LineBucket(start=start, end=end)


def location_signature_from_finding(
    finding: Mapping[str, Any],
    *,
    repo_name: Optional[str],
    bucket_size: int,
) -> Optional[LocationSignature]:
    """Return a LocationSignature for a finding or None if missing data."""

    fp_raw = finding.get("file_path")
    fp = normalize_file_path(str(fp_raw) if fp_raw is not None else None, repo_name)
    if not fp:
        return None

    ln = anchor_line(finding)
    if ln is None:
        return None

    b = bucket_for_line(ln, bucket_size=bucket_size)
    if not b:
        return None

    return LocationSignature(file=fp, bucket=b)


def iter_location_signatures(
    findings: Iterable[Mapping[str, Any]],
    *,
    repo_name: Optional[str],
    bucket_size: int,
) -> Iterator[Tuple[str, LocationSignature, Mapping[str, Any]]]:
    """Yield (signature_id, signature, finding) triples for findings."""
    for f in findings:
        sig = location_signature_from_finding(f, repo_name=repo_name, bucket_size=bucket_size)
        if sig is None:
            continue
        yield sig.id(), sig, f


_BAD_PATH_CHARS = re.compile(r"[^a-zA-Z0-9._\-]+")


def safe_dir_name(value: str, *, max_len: int = 140) -> str:
    """Create a filesystem-safe folder name from a signature or id."""
    v = (value or "").strip()
    if not v:
        return "empty"
    v = v.replace("/", "__").replace("\\", "__")
    v = v.replace("|", "--")
    v = _BAD_PATH_CHARS.sub("_", v)
    v = re.sub(r"_+", "_", v).strip("_")
    if not v:
        v = "empty"
    if len(v) > max_len:
        v = v[:max_len].rstrip("_")
    return v
