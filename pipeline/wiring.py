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
from pathlib import Path

from dotenv import load_dotenv

from pipeline.core import ROOT_DIR
from pipeline.pipeline import SASTBenchmarkPipeline


ENV_PATH: Path = ROOT_DIR / ".env"


def load_dotenv_if_present(dotenv_path: Path = ENV_PATH) -> None:
    """Load environment variables from a .env file (if present).

    Uses ``python-dotenv`` for consistent parsing across:
    - the pipeline wiring (CLI)
    - tool runners (e.g. Sonar / Aikido)

    Behavior:
    - If the file doesn't exist, no-op.
    - Values do **not** override existing environment variables.
    """

    if not dotenv_path.exists():
        return

    # Keep the same "do not override" semantics as our old custom loader.
    load_dotenv(dotenv_path, override=False)


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
