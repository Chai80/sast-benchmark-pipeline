"""Backwards-compatible shim.

Prefer importing from the new homes:
  - tools.normalize.common  (schema-block builders)
  - tools.io               (JSON IO + line reading helpers)

This file exists so older imports like `from tools.normalize_common import ...`
continue to work while the codebase moves to the package layout.
"""

from tools.normalize.common import *  # noqa: F401,F403
from tools.io import read_json, read_line_content, write_json  # noqa: F401
