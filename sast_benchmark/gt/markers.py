from __future__ import annotations

"""sast_benchmark.gt.markers

Ground-truth extraction from *in-repo marker comments*.

Why this exists
---------------
Suites can author GT in different ways (YAML catalogs, inline markers, etc.).
For branch-per-case micro-suites, it is often cleaner to keep GT *with the code*
it refers to.

This module provides a single, stable GT-marker parser used by:

- suite materialization (to compile a canonical gt_catalog.yaml when YAML isn't present)
- analysis (optional; for gt_source=markers/auto)

Supported marker formats
------------------------

1) Key/value single-line markers (recommended)

   # DURINN_GT id=sql_injection_1 track=sast set=core owasp=A03

2) Start/end block markers (lightweight)

   # GT:OWASP2021_A03_01_START
   ...
   # GT:OWASP2021_A03_01_END

The parser is intentionally *best-effort* and deterministic:
- ignores common VCS/build/venv dirs
- skips obvious binary files by extension
- returns items sorted for diffable outputs
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# Marker token for key/value comments (case-insensitive).
_DURINN_MARKER_RE = re.compile(r"\bDURINN_GT\b", re.IGNORECASE)

# Key/value parser: `key=value` separated by whitespace/commas/semicolons.
_KV_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*([^\s,;]+)")

# Lightweight start/end blocks: `GT:<ID>_START` / `GT:<ID>_END`
_GT_BLOCK_RE = re.compile(r"\bGT\s*:\s*(?P<id>[A-Za-z0-9_]+)_(?P<tag>START|END)\b", re.IGNORECASE)

# Optional: derive OWASP category from common IDs (e.g., OWASP2021_A03_01 -> A03)
_OWASP_FROM_ID_RE = re.compile(r"\bOWASP\w*_A(?P<num>\d{2})\b", re.IGNORECASE)


_DEFAULT_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "target",
}


_BINARY_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".tgz",
    ".7z",
    ".jar",
    ".class",
    ".exe",
    ".dll",
    ".so",
}


def _parse_kv_pairs(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _KV_RE.finditer(text or ""):
        k = m.group(1).strip().lower()
        v = m.group(2).strip()
        if k and v:
            out[k] = v
    return out


def _safe_relpath(p: Path, root: Path) -> str:
    try:
        rel = p.resolve().relative_to(root.resolve())
        return rel.as_posix()
    except Exception:
        return ""


def _normalize_track(kv: Dict[str, str]) -> str:
    return kv.get("track") or kv.get("category") or kv.get("type") or kv.get("kind") or "sast"


def _normalize_set(kv: Dict[str, str]) -> str:
    return kv.get("set") or kv.get("scope") or "default"


def _derive_owasp_from_id(gt_id: str) -> Optional[str]:
    if not gt_id:
        return None
    m = _OWASP_FROM_ID_RE.search(gt_id)
    if not m:
        return None
    return f"A{m.group('num')}"


def extract_gt_markers(
    repo_root: Path,
    *,
    ignore_dirs: Optional[Iterable[str]] = None,
    max_file_size_bytes: int = 1_000_000,
) -> List[Dict[str, Any]]:
    """Extract GT marker items from files under repo_root.

    Returns a list of dicts compatible with the analysis `gt_score` stage:

      {
        "id": "...",
        "file": "path/relative/to/repo",
        "start_line": 12,
        "end_line": 12,
        "track": "sast",
        "set": "default",
        # optional extra metadata:
        "owasp": "A03",
        "source": "durinn_marker" | "gt_block",
        "marker": "original line text (durinn markers only)"
      }
    """
    root = Path(repo_root).resolve()
    if not root.exists() or not root.is_dir():
        return []

    ignore = set(_DEFAULT_IGNORE_DIRS)
    if ignore_dirs:
        ignore |= {str(x) for x in ignore_dirs}

    kv_items: List[Dict[str, Any]] = []
    # (file, id) -> block info
    blocks: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for dirpath, dirnames, filenames in os.walk(root):
        # prune ignored dirs in-place
        dirnames[:] = [d for d in dirnames if d not in ignore and not d.startswith(".")]

        for fn in filenames:
            p = Path(dirpath) / fn
            # Skip obvious binary files by extension.
            if p.suffix.lower() in _BINARY_EXTS:
                continue

            try:
                if p.stat().st_size > max_file_size_bytes:
                    continue
            except Exception:
                continue

            rel = _safe_relpath(p, root)
            if not rel:
                continue

            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            # Quick reject: avoid line-splitting if neither marker is present.
            if not (_DURINN_MARKER_RE.search(text) or _GT_BLOCK_RE.search(text)):
                continue

            for idx, line in enumerate(text.splitlines(), start=1):
                # 1) DURINN_GT key/value markers
                if _DURINN_MARKER_RE.search(line):
                    kv = _parse_kv_pairs(line)
                    gt_id = kv.get("id") or f"marker:{rel}:{idx}"

                    track = _normalize_track(kv)
                    set_name = _normalize_set(kv)

                    item: Dict[str, Any] = {
                        "id": gt_id,
                        "file": rel,
                        "start_line": idx,
                        "end_line": idx,
                        "track": track,
                        "set": set_name,
                        "source": "durinn_marker",
                        "marker": line.strip(),
                    }

                    # Preserve additional metadata if present (e.g., owasp=A03).
                    # We intentionally do not overwrite the canonical keys above.
                    for k, v in kv.items():
                        if k in {"id", "track", "category", "type", "kind", "set", "scope"}:
                            continue
                        if k not in item:
                            item[k] = v

                    # Derive owasp from id if not explicitly provided.
                    if "owasp" not in item:
                        o = _derive_owasp_from_id(gt_id)
                        if o:
                            item["owasp"] = o

                    kv_items.append(item)

                # 2) GT block markers (START/END)
                m = _GT_BLOCK_RE.search(line)
                if m:
                    gt_id = m.group("id").strip()
                    tag = (m.group("tag") or "").strip().upper()
                    key = (rel, gt_id)
                    d = blocks.setdefault(
                        key,
                        {
                            "id": gt_id,
                            "file": rel,
                            "track": "sast",
                            "set": "default",
                            "source": "gt_block",
                        },
                    )

                    # Allow optional key=value metadata on the same line.
                    kv = _parse_kv_pairs(line)
                    if kv:
                        d["track"] = _normalize_track(kv)
                        d["set"] = _normalize_set(kv)
                        if kv.get("owasp"):
                            d["owasp"] = kv.get("owasp")

                    if tag == "START":
                        d["start_line"] = idx
                    elif tag == "END":
                        d["end_line"] = idx

                    # Derive owasp from id if present.
                    if "owasp" not in d:
                        o = _derive_owasp_from_id(gt_id)
                        if o:
                            d["owasp"] = o

    # Finalize blocks into items
    block_items: List[Dict[str, Any]] = []
    for (_rel, _gid), d in blocks.items():
        start = int(d.get("start_line") or d.get("end_line") or 0)
        end = int(d.get("end_line") or d.get("start_line") or 0)
        if start <= 0 and end <= 0:
            continue
        if start <= 0:
            start = end
        if end <= 0:
            end = start
        if end < start:
            start, end = end, start
        d["start_line"] = start
        d["end_line"] = end
        block_items.append(d)

    items = kv_items + block_items

    # Deterministic order for diffable outputs.
    items.sort(key=lambda it: (str(it.get("file") or ""), int(it.get("start_line") or 0), str(it.get("id") or "")))
    return items
