from __future__ import annotations

"""cli.utils.suite_picker

Small, self-contained helpers for selecting a local suite directory.

This module exists to keep interactive UX out of analysis orchestration.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from cli.ui import choose_from_menu


@dataclass(frozen=True)
class SuiteChoice:
    suite_dir: Path
    suite_id: str
    source: str  # "latest" | "picked"


def _is_suite_dir(p: Path) -> bool:
    return p.is_dir() and (p / "cases").is_dir()


def resolve_latest_suite_dir(suite_root: Path) -> Optional[Path]:
    """Resolve suite_root/LATEST.

    Supports:
      - LATEST as a symlink/dir pointing at a suite directory
      - LATEST as a file containing either a suite_id or a relative/absolute path
    """

    latest = suite_root / "LATEST"
    if not latest.exists():
        return None

    # Common: symlink to a directory (Path.is_dir() follows symlinks)
    if latest.is_dir():
        return latest.resolve()

    if latest.is_file():
        target = latest.read_text(encoding="utf-8").strip()
        if not target:
            return None
        p = Path(target)
        if not p.is_absolute():
            p = suite_root / p
        return p.resolve()

    return None


def list_local_suites(suite_root: Path) -> List[Path]:
    """List suite directories under suite_root."""
    out: List[Path] = []
    if not suite_root.exists():
        return out

    for p in suite_root.iterdir():
        if p.name == "LATEST":
            continue
        if p.is_file() and p.suffix == ".zip":
            continue
        if _is_suite_dir(p):
            out.append(p.resolve())

    out.sort(key=lambda x: x.name)
    return out


def prompt_for_suite(suite_root: Path) -> SuiteChoice:
    """Interactive prompt to select either LATEST or a local suite."""
    suite_root = suite_root.resolve()

    latest = resolve_latest_suite_dir(suite_root)
    suites = list_local_suites(suite_root)

    choice = choose_from_menu(
        "Choose a suite to analyze:",
        {
            "latest": f"Use LATEST ({latest.name if latest else 'not found'})",
            "pick": "Pick from local suites",
        },
    )

    if choice == "latest":
        if latest is None:
            raise SystemExit("LATEST suite is not available.")
        return SuiteChoice(suite_dir=latest, suite_id=latest.name, source="latest")

    if not suites:
        raise SystemExit(f"No suites found under {suite_root}")

    suite_id = choose_from_menu("Choose a local suite:", {p.name: p.name for p in suites})
    sel = suite_root / suite_id
    if not _is_suite_dir(sel):
        raise SystemExit(f"Selected suite is not a valid suite directory: {sel}")
    return SuiteChoice(suite_dir=sel.resolve(), suite_id=sel.name, source="picked")
