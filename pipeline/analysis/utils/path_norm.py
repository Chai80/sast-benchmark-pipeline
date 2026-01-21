from __future__ import annotations

import re
from typing import Optional, Sequence, Tuple


_SLASH_RE = re.compile(r"/+")


def normalize_file_path(path: str, *, repo_name: Optional[str] = None) -> str:
    """Normalize a file path so cross-tool comparisons are less noisy.

    Tools frequently emit absolute paths (especially Semgrep). For comparisons we
    want something closer to a repo-relative path.

    Heuristics
    ----------
    1) Normalize separators to "/"
    2) If repo_name is known and appears as a path segment, drop everything up to it.
    3) Strip leading "./"
    4) Collapse multiple slashes

    This is intentionally best-effort (not perfect). It should never raise.
    """
    if not path:
        return ""

    try:
        s = str(path).replace("\\", "/").strip()

        # Remove Windows drive letters (C:/...)
        if len(s) >= 2 and s[1] == ":":
            s = s[2:]

        # Prefer cutting at the repo_name segment when present.
        if repo_name:
            rn = str(repo_name).strip().strip("/")
            if rn:
                needle = f"/{rn}/"
                idx = s.lower().rfind(needle.lower())
                if idx != -1:
                    s = s[idx + len(needle) :]

        # Common tool output includes /repos/<repo>/...
        if s.startswith("/repos/") and repo_name:
            # /repos/<repo>/x -> x
            prefix = f"/repos/{repo_name}/"
            if s.lower().startswith(prefix.lower()):
                s = s[len(prefix) :]

        # Strip leading slash and dot segments
        s = s.lstrip("/")
        if s.startswith("./"):
            s = s[2:]

        s = _SLASH_RE.sub("/", s)
        return s
    except Exception:
        return str(path)


def normalize_exclude_prefix(prefix: str) -> str:
    """Normalize an exclude prefix into a repo-relative POSIX-ish form.

    This is intentionally a *lightweight* transformation. It is used for
    prefix-based scope filtering (not as a security boundary).

    Normalization rules
    -------------------
    - Convert path separators to "/"
    - Strip leading "./" segments
    - Strip leading slashes (keep comparisons repo-relative)
    - Strip trailing slashes (treat "benchmark" and "benchmark/" as equal)
    - Collapse duplicate separators
    """

    p = str(prefix or "").strip().replace("\\", "/")

    # Remove common shell-ish relative prefixes.
    while p.startswith("./"):
        p = p[2:]

    # Keep comparisons repo-relative.
    p = p.lstrip("/")

    # Make "benchmark/" and "benchmark" equivalent.
    p = p.rstrip("/")

    # Collapse duplicate separators.
    while "//" in p:
        p = p.replace("//", "/")

    return p


def normalize_exclude_prefixes(prefixes: Sequence[str] | None) -> Tuple[str, ...]:
    """Normalize + de-duplicate exclude prefixes while preserving order."""

    out: list[str] = []
    seen: set[str] = set()
    for raw in prefixes or []:
        p = normalize_exclude_prefix(str(raw))
        if not p:
            continue
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    return tuple(out)


def is_excluded_path(
    file_path: str,
    *,
    repo_name: str,
    exclude_prefixes: Sequence[str] | None,
) -> bool:
    """Return True if a finding path should be excluded by prefix.

    Parameters
    ----------
    file_path:
        Any file path (absolute or repo-relative). This function normalizes the
        path into a repo-relative form before checking prefixes.
    repo_name:
        Used by :func:`normalize_file_path` to strip legacy runs/<repo_name>/
        prefixes.
    exclude_prefixes:
        Repo-relative prefixes to exclude.

    Notes
    -----
    Prefix matching is directory-aware:
      - prefix "benchmark" excludes "benchmark" and "benchmark/..."
      - prefix "benchmark/" is treated the same
    """

    prefixes = exclude_prefixes or ()
    if not prefixes:
        return False

    fp = normalize_file_path(str(file_path or ""), repo_name=repo_name)
    if not fp:
        return False

    fp_n = normalize_exclude_prefix(fp)
    for raw in prefixes:
        pfx = normalize_exclude_prefix(str(raw))
        if not pfx:
            continue
        if fp_n == pfx or fp_n.startswith(pfx + "/"):
            return True
    return False
