#!/usr/bin/env python3
"""tools/core.py

Shared scanner plumbing used by tools/scan_*.py scripts.

This module is intentionally a **compatibility facade**.

Historically, scanner adapters imported utilities from :mod:`tools.core`. As the
pipeline grew, the implementation was split into smaller modules to keep each
file under control (and to reduce "utility gravity"):

* :mod:`tools.core_cmd`        - subprocess helpers
* :mod:`tools.core_git`        - git metadata helpers
* :mod:`tools.core_repo`       - repo acquisition helpers
* :mod:`tools.core_metadata`   - standard metadata.json builder
* :mod:`tools.core_maps`       - mapping loaders (e.g., CWE -> OWASP)
* :mod:`tools.core_normalize`  - deterministic normalization helpers
* :mod:`tools.core_root`       - :data:`ROOT_DIR`

Tool-specific parsing remains in each :mod:`tools.<tool>` package.
"""

from __future__ import annotations

# JSON + line-content helpers live in tools/io.py. We re-export them here for
# backwards compatibility.
from tools.io import read_json, write_json as _write_json, read_line_content as _read_line_content

# Re-export for scanner packages that historically imported `write_json` from
# tools.core.
write_json = _write_json
read_line_content = _read_line_content

from .core_root import ROOT_DIR

# Command helpers
from .core_cmd import CmdResult, which_or_raise, run_cmd

# Git helpers
from .core_git import (
    get_pipeline_git_commit,
    get_git_commit,
    get_git_branch,
    get_commit_author_info,
)

# Repo acquisition
from .core_repo import TargetRepo, acquire_repo, get_repo_name, clone_repo

# Standard run metadata
from .core_metadata import build_run_metadata, get_commit_author_info_compat

# Shared mappings
from .core_maps import load_cwe_to_owasp_map

# Normalization utilities
from .core_normalize import normalize_repo_relative_path, finalize_normalized_findings


__all__ = [
    # IO re-exports
    "read_json",
    "write_json",
    "read_line_content",
    # Root
    "ROOT_DIR",
    # Command helpers
    "CmdResult",
    "which_or_raise",
    "run_cmd",
    # Git helpers
    "get_pipeline_git_commit",
    "get_git_commit",
    "get_git_branch",
    "get_commit_author_info",
    # Repo helpers
    "get_repo_name",
    "clone_repo",
    "TargetRepo",
    "acquire_repo",
    # Metadata
    "get_commit_author_info_compat",
    "build_run_metadata",
    # Mappings
    "load_cwe_to_owasp_map",
    # Normalization
    "normalize_repo_relative_path",
    "finalize_normalized_findings",
]
