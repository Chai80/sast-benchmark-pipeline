"""tools/core_maps.py

Shared mapping loaders (e.g., CWE -> OWASP).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from .core_root import ROOT_DIR
from .io import read_json


def load_cwe_to_owasp_map(mappings_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Load mappings/cwe_to_owasp_top10_mitre.json.

    Returns a dict (possibly empty). Resolver supports different shapes.
    """
    mappings_dir = mappings_dir or (ROOT_DIR / "mappings")
    p = mappings_dir / "cwe_to_owasp_top10_mitre.json"
    if not p.exists():
        return {}
    try:
        data = read_json(p)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}
