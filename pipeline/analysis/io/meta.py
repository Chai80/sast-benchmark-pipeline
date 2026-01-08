from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional


def read_json_if_exists(path: Path) -> Optional[Dict[str, Any]]:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
