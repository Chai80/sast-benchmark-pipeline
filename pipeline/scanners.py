"""pipeline.scanners

Central registry of supported scanners and their static metadata.

Why this exists
---------------
Several parts of the pipeline need to agree on the *same* scanner facts:
- which scanners are supported (validation)
- which scanners are used by default (CLI defaults)
- human-friendly labels (menus / help text)
- which runner script to execute under ``tools/`` (command building)
- what benchmark tracks a scanner supports (best-effort filtering)

Historically these facts drifted across multiple files (CLI, core, ad-hoc checks).
This module makes the filesystem/execution layer consistent by defining them
*once*.

Important
---------
This module intentionally contains **no scanner-specific behavior**:
- no API calls
- no parsing logic
- no special-case CLI flags

That behavior belongs in ``tools/scan_*.py`` and normalization/analysis code.
This file is just the "menu" / wiring metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set


@dataclass(frozen=True)
class ScannerInfo:
    """Static metadata describing one scanner integration."""

    key: str
    label: str
    script: str
    tracks: frozenset[str]
    default: bool = True


# Canonical registry.
#
# NOTE: dict insertion order is preserved in modern Python, so the order here is
# the order used for DEFAULT_SCANNERS / DEFAULT_SCANNERS_CSV.
SCANNERS: Dict[str, ScannerInfo] = {
    "semgrep": ScannerInfo(
        key="semgrep",
        label="Semgrep",
        script="scan_semgrep.py",
        tracks=frozenset({"sast", "iac", "secrets"}),
        default=True,
    ),
    "snyk": ScannerInfo(
        key="snyk",
        label="Snyk Code",
        script="scan_snyk.py",
        tracks=frozenset({"sast"}),
        default=True,
    ),
    "sonar": ScannerInfo(
        key="sonar",
        label="SonarCloud",
        script="scan_sonar.py",
        tracks=frozenset({"sast"}),
        default=True,
    ),
    "aikido": ScannerInfo(
        key="aikido",
        label="Aikido",
        script="scan_aikido.py",
        tracks=frozenset({"sast", "sca", "iac", "secrets"}),
        default=True,
    ),
}


# Derived views (kept as plain collections for convenience/compatibility).
SUPPORTED_SCANNERS: Set[str] = set(SCANNERS.keys())

DEFAULT_SCANNERS: List[str] = [k for k, info in SCANNERS.items() if info.default]
DEFAULT_SCANNERS_CSV: str = ",".join(DEFAULT_SCANNERS)

SCANNER_LABELS: Dict[str, str] = {k: info.label for k, info in SCANNERS.items()}
SCANNER_SCRIPTS: Dict[str, str] = {k: info.script for k, info in SCANNERS.items()}

# Keep the legacy shape: Dict[str, set[str]]
SCANNER_TRACKS: Dict[str, set[str]] = {k: set(info.tracks) for k, info in SCANNERS.items()}
