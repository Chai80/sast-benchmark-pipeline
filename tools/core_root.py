"""tools/core_root.py

Shared *repository root* locator used by tools/* helper modules.

We intentionally keep this in a tiny module so other ``core_*`` modules can
import :data:`ROOT_DIR` without creating circular imports.
"""

from __future__ import annotations

from pathlib import Path


# Repo root = parent of tools/
ROOT_DIR = Path(__file__).resolve().parents[1]
