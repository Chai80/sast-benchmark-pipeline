"""pipeline.identifiers

Pure naming / identifier helpers.

Why this module exists
----------------------
Several layers need access to small, *pure* helpers for deriving stable IDs and
project keys (especially for SonarCloud):

* CLI (repo_id derivation from repo_url / local path)
* suite resolution (stable repo_id naming)
* scanner wiring hooks (derive args like Sonar project-key)

Historically these helpers lived in :mod:`pipeline.core`. But
:mod:`pipeline.core` also imports :mod:`pipeline.scanners` (to build correct
scanner commands), and :mod:`pipeline.scanners` needs some of these helpers.

That created an import-cycle pressure (handled via a lazy import). This module
breaks that coupling by providing a tiny, side-effect-free home for identifier
logic.
"""

from __future__ import annotations

import re

__all__ = [
    "sanitize_sonar_key_fragment",
    "repo_id_from_repo_url",
    "derive_sonar_project_key",
]


# SonarCloud project keys generally allow: letters, digits, '-', '_', '.', ':'
# We sanitize more aggressively to keep outputs stable across environments.
_SONAR_KEY_ALLOWED = re.compile(r"[^a-zA-Z0-9_.:]")


def sanitize_sonar_key_fragment(value: str) -> str:
    """Sanitize a string into something safe for Sonar project keys.

    This function is intentionally deterministic and conservative.

    Notes
    -----
    * Normalizes '-' -> '_' to avoid duplicate projects when a repo name
      contains dashes.
    * Collapses repeated underscores.
    * Ensures the result is non-empty.
    * Sonar requires at least one non-digit character; prefixes "p_" if the
      sanitized value is all digits.

    Examples
    --------
    "juice-shop" -> "juice_shop"
    "OWASP BenchmarkJava" -> "OWASP_BenchmarkJava"
    "123" -> "p_123"
    """  # noqa: D401

    v = (value or "").strip()
    v = v.replace("-", "_")

    # Replace anything outside [a-zA-Z0-9_.:] with underscore
    v = _SONAR_KEY_ALLOWED.sub("_", v)
    v = re.sub(r"_+", "_", v).strip("_")

    if not v:
        raise ValueError("Empty Sonar key fragment after sanitization.")

    # Sonar requires at least one non-digit char; prefix if needed
    if v.isdigit():
        v = f"p_{v}"

    return v


def repo_id_from_repo_url(repo_url: str) -> str:
    """Derive a stable repo_id from a git URL."""

    last = (repo_url or "").rstrip("/").split("/")[-1]
    if last.endswith(".git"):
        last = last[:-4]
    return sanitize_sonar_key_fragment(last)


def derive_sonar_project_key(organization_key: str, repo_id: str) -> str:
    """Return a stable SonarCloud project key like: ORG_REPO."""

    org = sanitize_sonar_key_fragment(organization_key)
    rid = sanitize_sonar_key_fragment(repo_id)
    return f"{org}_{rid}"
