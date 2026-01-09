"""pipeline.wiring

This module is the **composition root** for the Python runtime.

"Composition root" means: the single place where we *assemble* the running
application from its building blocks:

- load configuration / environment variables
- choose real vs stub implementations (useful for testing)
- build the high-level pipeline facade object

Keeping this wiring in one place prevents configuration and dependency setup
from being duplicated across entrypoints (CLI, scripts, notebooks, CI).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from pipeline.core import ROOT_DIR
from pipeline.pipeline import SASTBenchmarkPipeline


ENV_PATH: Path = ROOT_DIR / ".env"


def load_dotenv_if_present(dotenv_path: Path = ENV_PATH) -> None:
    """Minimal .env loader.

    Loads KEY=VALUE lines into ``os.environ`` if the key is not already set.

    Design goals:
    - no third-party dependency
    - simple quoting support
    - safe-ish comment stripping for common cases
    """

    if not dotenv_path.exists():
        return

    for raw in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, val = line.split("=", 1)
        key = key.strip()
        raw_val = val.strip()

        # Quoted value
        if (raw_val.startswith('"') and raw_val.endswith('"')) or (
            raw_val.startswith("'") and raw_val.endswith("'")
        ):
            parsed_val = raw_val[1:-1]
        else:
            # Strip inline comments only when preceded by whitespace: "VALUE   # comment"
            parsed_val = re.split(r"\s+#", raw_val, maxsplit=1)[0].strip()
            parsed_val = parsed_val.strip('"').strip("'")

        parsed_val = parsed_val.replace("\r", "")
        if key and key not in os.environ:
            os.environ[key] = parsed_val


def build_pipeline(*, load_dotenv: bool = True) -> SASTBenchmarkPipeline:
    """Build the high-level pipeline facade.

    This is intentionally simple today. As the repo grows, this becomes the
    place to:

    - build scanner registries
    - configure logging
    - swap implementations for tests
    """

    if load_dotenv:
        load_dotenv_if_present(ENV_PATH)

    return SASTBenchmarkPipeline()
