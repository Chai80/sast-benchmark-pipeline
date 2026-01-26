"""pipeline.suites.suite_py_loader

Load suite definitions from a Python file.

Runtime policy:
- YAML/JSON must NOT drive execution (orchestration).
- Suite plans must be expressed as typed Python objects.

A Python suite file should export one of:
- SUITE_DEF: pipeline.suites.suite_definition.SuiteDefinition
- SUITE_DEFINITION: SuiteDefinition (alias)
- SUITE: SuiteDefinition (alias)
- SUITE_RAW: dict compatible with SuiteDefinition.from_dict()

This module is intentionally small and does not depend on scanner logic.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

from pipeline.suites.suite_definition import SuiteDefinition


def _load_module_from_path(path: Path) -> ModuleType:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"Suite file not found: {p}")
    if p.suffix.lower() != ".py":
        raise ValueError(f"Suite file must be a .py file: {p}")
    mod_name = f"durinn_suite_{p.stem}_{abs(hash(str(p)))}"
    spec = importlib.util.spec_from_file_location(mod_name, str(p))
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to import suite file: {p}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[assignment]
    return mod


def load_suite_py(path: str | Path) -> SuiteDefinition:
    """Load a suite definition from a Python file."""
    mod = _load_module_from_path(Path(path))
    candidate: Any = None
    for name in ("SUITE_DEF", "SUITE_DEFINITION", "SUITE", "SUITE_RAW"):
        if hasattr(mod, name):
            candidate = getattr(mod, name)
            break

    if candidate is None:
        raise ValueError("Suite .py must export SUITE_DEF (SuiteDefinition) or SUITE_RAW (dict).")

    if isinstance(candidate, SuiteDefinition):
        return candidate

    if isinstance(candidate, dict):
        return SuiteDefinition.from_dict(candidate)

    raise TypeError(
        f"Unsupported suite export type: {type(candidate)}. " "Expected SuiteDefinition or dict."
    )
