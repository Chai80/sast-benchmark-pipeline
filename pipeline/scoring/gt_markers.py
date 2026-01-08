from __future__ import annotations

"""pipeline.scoring.gt_markers

Ground-truth extraction from *in-repo marker comments*.

Why markers?
------------
YAML/JSON GT catalogs are powerful, but they are also easy to accidentally drift
or misapply across branches. For branch-per-case micro-suites, it is often
cleaner to keep GT *with the code* it refers to.

This module looks for comment markers like:

  # DURINN_GT id=sql_injection_1 track=sast set=core

and turns them into GT items compatible with the analysis `gt_score` stage.

Marker format (v0)
------------------
- Marker token: ``DURINN_GT`` (case-insensitive)
- Key-value pairs: ``key=value`` separated by whitespace, commas, or semicolons

Recognized keys:
- id: stable identifier for the GT item (optional; auto-derived if missing)
- track: arbitrary grouping label (default: "sast")
- set: arbitrary grouping label (default: "default")
- end: end line number for a multi-line range (optional)

The marker line number becomes ``start_line``.
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


_MARKER_RE = re.compile(r"\bDURINN_GT\b", re.IGNORECASE)
_KV_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_-]*)\s*=\s*([^\s,;]+)")


_DEFAULT_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "target",
    "vendor",
    "runs",
    "tool_runs",
    "analysis",
    "gt",
    ".scannerwork",
    ".aikidotmp",
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
    ".dylib",
    ".bin",
}


def _safe_relpath(path: Path, root: Path) -> Optional[str]:
    """Return a root-relative POSIX path, or None if not under root."""
    try:
        rel = path.resolve().relative_to(root.resolve())
        return rel.as_posix()
    except Exception:
        return None


def _parse_kv_pairs(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _KV_RE.finditer(text or ""):
        k = m.group(1).strip().lower()
        v = m.group(2).strip()
        if k and v:
            out[k] = v
    return out


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
        "set": "default"
      }
    """

    root = Path(repo_root).resolve()
    if not root.exists() or not root.is_dir():
        return []

    ignore = set(_DEFAULT_IGNORE_DIRS)
    if ignore_dirs:
        ignore |= {str(x) for x in ignore_dirs}

    items: List[Dict[str, Any]] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Mutate dirnames in-place to prune traversal.
        dirnames[:] = [d for d in dirnames if d not in ignore]

        for fname in filenames:
            p = Path(dirpath) / fname

            # Skip symlinks (avoid escaping repo_root).
            try:
                if p.is_symlink():
                    continue
            except Exception:
                continue

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

            # Quick reject: avoid line-splitting if marker token isn't present.
            if not _MARKER_RE.search(text):
                continue

            for idx, line in enumerate(text.splitlines(), start=1):
                if not _MARKER_RE.search(line):
                    continue

                kv = _parse_kv_pairs(line)
                gt_id = kv.get("id") or f"marker:{rel}:{idx}"
                track = kv.get("track") or "sast"
                set_name = kv.get("set") or "default"

                end_line: Optional[int] = None
                if "end" in kv:
                    try:
                        end_line = int(kv["end"])
                    except Exception:
                        end_line = None

                items.append(
                    {
                        "id": gt_id,
                        "file": rel,
                        "start_line": idx,
                        "end_line": end_line or idx,
                        "track": track,
                        "set": set_name,
                        "source": "marker",
                        "marker": line.strip(),
                    }
                )

    # Deterministic order for diffable outputs.
    items.sort(key=lambda it: (str(it.get("file") or ""), int(it.get("start_line") or 0), str(it.get("id") or "")))
    return items
