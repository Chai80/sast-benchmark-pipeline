from __future__ import annotations

"""cli.utils.suite_picker

Small, self-contained helpers for selecting a local suite directory.

This module exists to keep interactive UX out of analysis orchestration.

Special pointers
----------------
The suite root may contain small pointer files to make non-interactive
workflows deterministic:

- ``runs/suites/LATEST``     -> most recent suite run id
- ``runs/suites/LATEST_QA``  -> most recent QA calibration suite run id

Pointers are plain text files containing either:
- a suite id (folder name under runs/suites), or
- a relative/absolute path to a suite directory

They may also be implemented as symlinks on some platforms.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from cli.ui import choose_from_menu


@dataclass(frozen=True)
class SuiteChoice:
    suite_dir: Path
    suite_id: str
    source: str  # "latest" | "latestqa" | "picked"


def _is_suite_dir(p: Path) -> bool:
    return p.is_dir() and (p / "cases").is_dir()


def _resolve_pointer_dir(suite_root: Path, pointer_name: str) -> Optional[Path]:
    """Resolve suite_root/<pointer_name>.

    Supports:
      - pointer as a symlink/dir pointing at a suite directory
      - pointer as a file containing either a suite_id or a relative/absolute path
    """

    suite_root = suite_root.resolve()
    ptr = suite_root / pointer_name
    if not ptr.exists():
        return None

    # Common: symlink to a directory (Path.is_dir() follows symlinks)
    if ptr.is_dir():
        return ptr.resolve()

    if ptr.is_file():
        target = ptr.read_text(encoding="utf-8").strip()
        if not target:
            return None
        p = Path(target)
        if not p.is_absolute():
            p = suite_root / p
        return p.resolve()

    return None


def resolve_latest_suite_dir(suite_root: Path) -> Optional[Path]:
    """Resolve suite_root/LATEST."""

    return _resolve_pointer_dir(suite_root, "LATEST")


def resolve_latest_qa_suite_dir(suite_root: Path) -> Optional[Path]:
    """Resolve suite_root/LATEST_QA (latest QA calibration suite run)."""

    return _resolve_pointer_dir(suite_root, "LATEST_QA")


def resolve_previous_suite_dir(suite_root: Path) -> Optional[Path]:
    """Resolve the suite directory immediately *preceding* LATEST.

    This is a deterministic helper used by non-interactive workflows (CI).

    Definition
    ----------
    "previous" means: the suite directory that sorts immediately before the
    resolved LATEST suite when listing local suite directories under
    ``runs/suites``.

    Notes
    -----
    - We intentionally avoid using filesystem mtimes here because analysis runs
      can touch old suites and make mtimes misleading.
    - Suite ids are timestamp-based by default, so lexicographic order matches
      chronology in common workflows.
    """

    suite_root = suite_root.resolve()

    latest = resolve_latest_suite_dir(suite_root)
    if latest is None:
        return None

    suites = list_local_suites(suite_root)
    if not suites:
        return None

    latest_r = latest.resolve()

    idx = None
    for i, p in enumerate(suites):
        try:
            if p.resolve() == latest_r:
                idx = i
                break
        except Exception:
            continue

    if idx is not None and idx > 0:
        return suites[idx - 1]

    prev: Optional[Path] = None
    for p in suites:
        if p.name < latest_r.name:
            prev = p
    return prev


def _read_suite_kind(suite_dir: Path) -> Optional[str]:
    """Best-effort load suite_kind from suite.json."""

    try:
        p = suite_dir / "suite.json"
        if not p.exists():
            return None
        raw = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return None
        sk = raw.get("suite_kind")
        return sk if isinstance(sk, str) and sk.strip() else None
    except Exception:
        return None


def _is_qa_suite_dir(suite_dir: Path) -> bool:
    """Heuristic: identify QA calibration suites.

    Primary signal (new runs): suite.json has suite_kind == "qa_calibration".
    Backward-compatible signals (older runs): presence of QA runbook artifacts.
    """

    if not _is_suite_dir(suite_dir):
        return False

    sk = (_read_suite_kind(suite_dir) or "").strip().lower()
    if sk == "qa_calibration":
        return True

    analysis_dir = suite_dir / "analysis"
    if (analysis_dir / "qa_manifest.json").exists():
        return True
    if (analysis_dir / "qa_calibration_manifest.json").exists():
        return True
    if (analysis_dir / "qa_calibration_checklist.txt").exists():
        return True

    return False


def list_local_suites(suite_root: Path) -> List[Path]:
    """List suite directories under suite_root."""

    out: List[Path] = []
    suite_root = suite_root.resolve()
    if not suite_root.exists():
        return out

    for p in suite_root.iterdir():
        # Skip pointer files/dirs
        if p.name in ("LATEST", "LATEST_QA"):
            continue
        if p.is_file() and p.suffix == ".zip":
            continue
        if _is_suite_dir(p):
            out.append(p.resolve())

    out.sort(key=lambda x: x.name)
    return out


def list_local_qa_suites(suite_root: Path) -> List[Path]:
    """List only QA calibration suites under suite_root."""

    suites = list_local_suites(suite_root)
    return [p for p in suites if _is_qa_suite_dir(p)]


def resolve_previous_qa_suite_dir(suite_root: Path) -> Optional[Path]:
    """Resolve the QA suite directory immediately preceding LATEST_QA.

    Definition matches resolve_previous_suite_dir but is computed over the
    filtered set of QA calibration suites.
    """

    suite_root = suite_root.resolve()

    latest = resolve_latest_qa_suite_dir(suite_root)
    qa_suites = list_local_qa_suites(suite_root)
    if not qa_suites:
        return None

    # If no pointer exists, fall back to lexicographically latest QA suite.
    latest_r = latest.resolve() if latest is not None else qa_suites[-1].resolve()

    idx = None
    for i, p in enumerate(qa_suites):
        try:
            if p.resolve() == latest_r:
                idx = i
                break
        except Exception:
            continue

    if idx is not None and idx > 0:
        return qa_suites[idx - 1]

    prev: Optional[Path] = None
    for p in qa_suites:
        if p.name < latest_r.name:
            prev = p
    return prev


def resolve_suite_dir_ref(suite_root: Path, suite_ref: str) -> Optional[Path]:
    """Resolve a suite directory by id or special ref.

    Supported refs:
      - "latest": resolve suite_root/LATEST
      - "previous" (or "prev"): resolve suite immediately before LATEST
      - "latestqa" (or "latest_qa"): resolve suite_root/LATEST_QA
      - "previousqa" (or "prevqa"): resolve QA suite immediately before LATEST_QA
      - any other string: treated as a suite_id folder name under suite_root
    """

    suite_root = suite_root.resolve()
    ref = str(suite_ref or "").strip()
    if not ref:
        return None

    low = ref.lower().replace("-", "_")
    if low == "latest":
        return resolve_latest_suite_dir(suite_root)
    if low in ("previous", "prev"):
        return resolve_previous_suite_dir(suite_root)

    if low in ("latestqa", "latest_qa"):
        return resolve_latest_qa_suite_dir(suite_root)
    if low in ("previousqa", "prevqa", "previous_qa", "prev_qa"):
        return resolve_previous_qa_suite_dir(suite_root)

    cand = (suite_root / ref).resolve()
    if _is_suite_dir(cand):
        return cand
    return None


def prompt_for_suite(suite_root: Path) -> SuiteChoice:
    """Interactive prompt to select either LATEST, LATEST_QA, or a local suite."""

    suite_root = suite_root.resolve()

    latest = resolve_latest_suite_dir(suite_root)
    latestqa = resolve_latest_qa_suite_dir(suite_root)
    suites = list_local_suites(suite_root)

    options = {
        "latest": f"Use LATEST ({latest.name if latest else 'not found'})",
        "latestqa": f"Use LATEST_QA ({latestqa.name if latestqa else 'not found'})",
        "pick": "Pick from local suites",
    }

    choice = choose_from_menu("Choose a suite to analyze:", options)

    if choice == "latest":
        if latest is None:
            raise SystemExit("LATEST suite is not available.")
        return SuiteChoice(suite_dir=latest, suite_id=latest.name, source="latest")

    if choice == "latestqa":
        if latestqa is None:
            raise SystemExit("LATEST_QA suite is not available.")
        return SuiteChoice(suite_dir=latestqa, suite_id=latestqa.name, source="latestqa")

    if not suites:
        raise SystemExit(f"No suites found under {suite_root}")

    suite_id = choose_from_menu("Choose a local suite:", {p.name: p.name for p in suites})
    sel = suite_root / suite_id
    if not _is_suite_dir(sel):
        raise SystemExit(f"Selected suite is not a valid suite directory: {sel}")
    return SuiteChoice(suite_dir=sel.resolve(), suite_id=sel.name, source="picked")
