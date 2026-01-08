from __future__ import annotations

import re
from typing import Optional


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
