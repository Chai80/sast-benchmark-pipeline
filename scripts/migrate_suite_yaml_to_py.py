#!/usr/bin/env python3
"""
One-time migration script: YAML suite definition -> Python suite definition.

Usage:
  python scripts/migrate_suite_yaml_to_py.py path/to/suite.yaml path/to/suite.py

The output .py will export:
  SUITE_DEF = SuiteDefinition.from_dict(SUITE_RAW)
"""

from __future__ import annotations

import pprint
import sys
from pathlib import Path

from pipeline.suites.suite_definition import load_suite_yaml


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("Usage: python scripts/migrate_suite_yaml_to_py.py <suite.yaml> <out.py>")
        return 2

    src = Path(argv[1]).expanduser().resolve()
    dst = Path(argv[2]).expanduser().resolve()

    if src.suffix.lower() not in (".yaml", ".yml"):
        print(f"Input must be .yaml/.yml: {src}")
        return 2

    try:
        suite_def = load_suite_yaml(src)
    except ModuleNotFoundError as e:
        print("PyYAML is required for migration only. Install it with: pip install pyyaml")
        print(f"Details: {e}")
        return 2

    raw = suite_def.to_dict()
    raw_py = pprint.pformat(raw, indent=2, sort_dicts=True)

    dst.parent.mkdir(parents=True, exist_ok=True)
    content = (
        "from pipeline.suites.suite_definition import SuiteDefinition\n\n"
        f"SUITE_RAW = {raw_py}\n\n"
        "SUITE_DEF = SuiteDefinition.from_dict(SUITE_RAW)\n"
    )
    dst.write_text(content, encoding="utf-8")
    print(f"✅ Wrote: {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
