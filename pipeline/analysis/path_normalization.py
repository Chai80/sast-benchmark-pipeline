"""pipeline.analysis.path_normalization

Small, pure utilities for making tool-reported file paths comparable.

Why this exists
---------------
Different scanners sometimes disagree on whether a path is repo-relative or
includes an extra repo-name prefix (for example:
"juice-shop/routes/search.ts" vs "routes/search.ts").

For analysis/metrics that key on (file_path, classification_code) signatures,
this can create false "unique" items that are actually the same hotspot.

We intentionally keep this normalization *out of scanner scripts* so:
  - you don't need to rescan old runs
  - scanners remain focused on scanning + normalization into the common schema

This module is safe to use at comparison time (metrics/analysis steps).
"""

from __future__ import annotations

import re


_DUP_SLASH_RE = re.compile(r"/+")


def normalize_file_path(file_path: str | None, repo_name: str | None) -> str | None:
    """Normalize a file path string for cross-tool comparisons.

    The goal is *not* to fully resolve a filesystem path. We only apply a
    minimal set of transformations that make different tool outputs comparable.

    Normalization rules
    -------------------
    - Convert Windows separators: ``\\`` → ``/``
    - Strip leading ``./`` segments
    - Strip leading ``/`` (avoid accidental absolute paths)
    - Collapse duplicate slashes (``foo//bar`` → ``foo/bar``)
    - If the path starts with ``{repo_name}/``, strip that prefix

    Examples
    --------
    >>> normalize_file_path('juice-shop/lib/insecurity.ts', 'juice-shop')
    'lib/insecurity.ts'
    >>> normalize_file_path('./routes/search.ts', 'juice-shop')
    'routes/search.ts'
    >>> normalize_file_path('\\\\juice-shop\\\\routes\\\\a.ts', 'juice-shop')
    'routes/a.ts'
    """

    if not file_path:
        return None

    # 1) Unify separators and trim whitespace
    # Use the single backslash character here (Windows paths).
    p = str(file_path).strip().replace("\\", "/")

    # 2) Strip leading "./" segments (repeat to handle "././foo")
    while p.startswith("./"):
        p = p[2:]

    # 3) Strip leading slashes (keep repo-relative)
    p = p.lstrip("/")

    # 4) Collapse duplicate slashes
    p = _DUP_SLASH_RE.sub("/", p)

    # 5) Strip optional repo-name prefix
    if repo_name:
        rn = str(repo_name).strip().strip("/")
        if rn:
            prefix = rn + "/"
            if p.startswith(prefix):
                p = p[len(prefix):]

    p = p.strip()
    return p or None
