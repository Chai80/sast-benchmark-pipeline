"""pipeline.analysis.location_signatures

Shared helpers for location-based hotspot alignment.

This module is intentionally dependency-light:
- No scanner-specific logic
- No CWE/OWASP mapping
- Only uses normalized finding fields that should exist across tools

Why this exists
---------------
Once you introduce location-based alignment, you'll need the same path + line
logic in multiple places (matrix generation, drilldown exporters, metrics).
Putting it in one place prevents signature drift and spaghetti.

Two ways to align by "location"
-------------------------------
1) Fixed buckets (legacy):
   - signature: <file>|L<bucket_start>-<bucket_end>
   - bucket size is fixed (e.g. 10 lines)

2) Line-tolerance clusters (recommended for "same code" evidence):
   - cluster across *all* tools' findings in a file
   - merge nearby findings into variable-width spans
   - signature: <file>|L<cluster_start>-<cluster_end>

Clustering avoids bucket boundary artifacts (e.g. line 39 vs 40 landing in
separate buckets) while staying simple and interpretable.

Signature format
----------------
We keep signatures readable and stable for spreadsheets and folder names.

    <normalized_file_path>|L<start>-<end>

Where start/end are 1-indexed line numbers.

Example:
    routes/search.ts|L21-30
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple

from pipeline.analysis.path_normalization import normalize_file_path


@dataclass(frozen=True)
class LineBucket:
    """A span of lines.

    Historical name is "LineBucket" because the first implementation used
    fixed-size buckets. It also works as a variable-width span for clustering.
    """

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


# ---------------------------------------------------------------------------
# Legacy fixed-size bucketing
# ---------------------------------------------------------------------------

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
    """Return a LocationSignature for a finding or None if missing data.

    This is the legacy fixed-size bucketing strategy.
    """

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
    """Yield (signature_id, signature, finding) triples for findings (bucketed)."""
    for f in findings:
        sig = location_signature_from_finding(f, repo_name=repo_name, bucket_size=bucket_size)
        if sig is None:
            continue
        yield sig.id(), sig, f


# ---------------------------------------------------------------------------
# Recommended line-tolerance clustering (cross-tool)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LocationPoint:
    """A single (file, line) observation from a tool.

    This object retains a pointer to the original finding so the caller can
    export evidence packs.

    `finding` is excluded from hashing/comparisons so LocationPoint remains
    usable in sets/dicts if needed.
    """

    tool: str
    file: str
    line: int
    finding: Mapping[str, Any] = field(compare=False, hash=False, repr=False)


def iter_location_points(
    findings: Iterable[Mapping[str, Any]],
    *,
    tool: str,
    repo_name: Optional[str],
    dedupe_by_finding_id: bool = True,
) -> Iterator[LocationPoint]:
    """Yield LocationPoints for findings that have a usable file path + line.

    We dedupe by finding_id by default because some tools can emit duplicates.
    """

    seen_ids: set[str] = set()

    for f in findings:
        if dedupe_by_finding_id:
            fid = f.get("finding_id")
            if isinstance(fid, str) and fid:
                if fid in seen_ids:
                    continue
                seen_ids.add(fid)

        fp_raw = f.get("file_path")
        fp = normalize_file_path(str(fp_raw) if fp_raw is not None else None, repo_name)
        if not fp:
            continue

        ln = anchor_line(f)
        if ln is None or ln <= 0:
            continue

        yield LocationPoint(tool=str(tool), file=fp, line=int(ln), finding=f)


def cluster_location_points(
    points: Iterable[LocationPoint],
    *,
    tolerance: int,
) -> List[Tuple[LocationSignature, List[LocationPoint]]]:
    """Cluster LocationPoints into per-file spans.

    Clustering rule (simple + interpretable):
      - In the same file, sort points by line.
      - Start a cluster.
      - Add the next point to the current cluster if:
            next_line <= current_cluster_end + tolerance
        otherwise, close the cluster and start a new one.

    This is effectively a 1D single-linkage clustering on anchor lines.

    Parameters
    ----------
    tolerance:
        Maximum gap (in lines) allowed between adjacent points in the same
        cluster.

        Example: tolerance=3 means lines 10 and 13 are clustered, but 10 and 14
        are not (unless there is a bridging point between them).
    """

    if not isinstance(tolerance, int) or tolerance < 0:
        raise ValueError(f"tolerance must be a non-negative int, got: {tolerance!r}")

    by_file: Dict[str, List[LocationPoint]] = {}
    for p in points:
        by_file.setdefault(p.file, []).append(p)

    clusters: List[Tuple[LocationSignature, List[LocationPoint]]] = []

    for fp, pts in by_file.items():
        pts.sort(key=lambda p: p.line)

        cur: List[LocationPoint] = []
        start = end = 0

        for p in pts:
            if not cur:
                cur = [p]
                start = end = p.line
                continue

            if p.line <= end + tolerance:
                cur.append(p)
                end = p.line  # sorted
                continue

            # flush
            sig = LocationSignature(file=fp, bucket=LineBucket(start=start, end=end))
            clusters.append((sig, cur))

            # start new
            cur = [p]
            start = end = p.line

        if cur:
            sig = LocationSignature(file=fp, bucket=LineBucket(start=start, end=end))
            clusters.append((sig, cur))

    # Deterministic ordering
    clusters.sort(key=lambda x: (x[0].file, x[0].bucket.start, x[0].bucket.end))
    return clusters


def build_location_cluster_index(
    *,
    findings_by_tool: Mapping[str, Iterable[Mapping[str, Any]]],
    repo_name_by_tool: Mapping[str, Optional[str]],
    tolerance: int,
) -> Tuple[List[LocationSignature], Dict[str, Dict[str, List[Mapping[str, Any]]]]]:
    """Build a cross-tool cluster index.

    Returns
    -------
    (clusters, idx_by_tool)

    clusters:
        Ordered list of cluster LocationSignatures.

    idx_by_tool:
        Dict[tool][cluster_signature_id] -> list[findings]

    Why this helper exists
    ----------------------
    If you cluster per-tool, cluster IDs drift (different tools have different
    numbers of findings). For cross-tool comparison you want *one* canonical set
    of clusters per run, built from the union of all tools' location points.
    """

    points: List[LocationPoint] = []
    for tool, findings in findings_by_tool.items():
        rn = repo_name_by_tool.get(tool)
        points.extend(list(iter_location_points(findings, tool=tool, repo_name=rn, dedupe_by_finding_id=True)))

    clustered = cluster_location_points(points, tolerance=tolerance)

    idx_by_tool: Dict[str, Dict[str, List[Mapping[str, Any]]]] = {t: {} for t in findings_by_tool.keys()}
    clusters: List[LocationSignature] = []

    for sig, members in clustered:
        clusters.append(sig)
        sid = sig.id()
        for m in members:
            idx_by_tool.setdefault(m.tool, {}).setdefault(sid, []).append(m.finding)

    return clusters, idx_by_tool


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------


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
