from __future__ import annotations

import argparse
import fnmatch
import re
from pathlib import Path
from typing import List, Optional

from cli.common import parse_csv
from pipeline.core import ROOT_DIR as PIPELINE_ROOT_DIR
from pipeline.suites.suite_definition import SuiteCase, SuiteDefinition


ROOT_DIR = PIPELINE_ROOT_DIR


def _default_owasp_micro_suite_worktrees_root() -> Optional[Path]:
    """Default micro-suite worktrees root (if present on disk).

    Keeps the QA calibration runbook deterministic for our current OWASP micro-suites.
    If the default path doesn't exist, callers should fall back to explicit
    --worktrees-root/--cases-from.
    """

    p = ROOT_DIR / "repos" / "worktrees" / "durinn-owasp2021-python-micro-suite"
    return p if p.is_dir() else None


def _default_owasp_micro_suite_cases_csv() -> Optional[Path]:
    """Default deterministic case list for the micro-suite QA (if present)."""

    p = (
        ROOT_DIR
        / "examples"
        / "suite_inputs"
        / "durinn-owasp2021-python-micro-suite_cases.csv"
    )
    return p if p.is_file() else None


# --------------------------
# QA calibration helpers
# --------------------------

_OWASP_ID_RE = re.compile(r"\bA(0[1-9]|10)\b", flags=re.IGNORECASE)


def _detect_owasp_id(*texts: object) -> Optional[str]:
    """Detect an OWASP Top 10 id (A01..A10) from free-form text fields."""

    for t in texts:
        if not t:
            continue
        m = _OWASP_ID_RE.search(str(t))
        if m:
            return f"A{m.group(1)}"
    return None


def _normalize_owasp_id(token: str) -> str:
    """Normalize inputs like 'a3'/'A03' -> 'A03'."""

    s = str(token or "").strip().upper()
    m = re.match(r"^A?(\d{1,2})$", s)
    if not m:
        return s
    n = int(m.group(1))
    return f"A{n:02d}"


def _expand_owasp_token(token: str) -> List[str]:
    """Expand an OWASP selector token.

    Supports:
      - A03
      - A01-A10
      - A01..A10
      - all
    """

    raw = str(token or "").strip()
    if not raw:
        return []

    # Normalize unicode dashes that sometimes show up in pasted text.
    raw = raw.replace("–", "-").replace("—", "-")

    if raw.strip().lower() in {"all"}:
        return [f"A{i:02d}" for i in range(1, 11)]

    m = re.match(r"(?i)^A?(\d{1,2})\s*(?:\.\.|-)\s*A?(\d{1,2})$", raw)
    if m:
        a = int(m.group(1))
        b = int(m.group(2))
        lo, hi = (a, b) if a <= b else (b, a)
        lo = max(lo, 1)
        hi = min(hi, 10)
        return [f"A{i:02d}" for i in range(lo, hi + 1)]

    return [_normalize_owasp_id(raw)]


def _parse_qa_owasp_spec(raw: str) -> List[str]:
    """Parse the --qa-owasp argument into a list of normalized IDs."""

    out: List[str] = []
    seen: set[str] = set()
    for tok in parse_csv(raw):
        for oid in _expand_owasp_token(tok):
            if not oid:
                continue
            if oid not in seen:
                seen.add(oid)
                out.append(oid)
    return out


def _qa_target_owasp_ids(args: argparse.Namespace) -> List[str]:
    """Return the OWASP ids included by this QA run."""

    raw = str(getattr(args, "qa_owasp", "") or "").strip()
    if raw:
        ids = _parse_qa_owasp_spec(raw)
        if ids:
            return ids

    scope = str(getattr(args, "qa_scope", "smoke") or "smoke").lower()
    if scope == "full":
        return [f"A{i:02d}" for i in range(1, 11)]

    # Default: smoke slice.
    return ["A03", "A07"]


def _qa_parse_case_selectors(raw: Optional[str]) -> List[str]:
    return [s for s in parse_csv(raw or "") if s]


def _qa_matches_selector(value: str, selector: str) -> bool:
    """Match a selector against a value.

    If selector contains glob metacharacters (*, ?, [), uses fnmatch.
    Otherwise does a case-insensitive substring match.
    """

    v = (value or "").lower()
    s = (selector or "").strip().lower()
    if not s:
        return False
    if any(ch in s for ch in ("*", "?", "[")):
        return fnmatch.fnmatch(v, s)
    return s in v


def _infer_case_owasp_id(sc: SuiteCase) -> Optional[str]:
    c = sc.case
    return _detect_owasp_id(c.case_id, c.branch, c.label)


def _filter_suite_def_for_qa(
    suite_def: SuiteDefinition,
    *,
    selectors: List[str],
    wanted_owasp_ids: List[str],
) -> SuiteDefinition:
    """Return a suite definition restricted to the QA slice.

    NOTE: This helper is currently not used by ``run_suite_mode`` directly,
    but is kept as a stable internal building block for future CLI tightening.
    """

    selected: List[SuiteCase] = []
    skipped: List[SuiteCase] = []

    if selectors:
        for sc in suite_def.cases:
            c = sc.case
            hay = [str(c.case_id or ""), str(c.branch or ""), str(c.label or "")]
            if any(_qa_matches_selector(v, sel) for sel in selectors for v in hay):
                selected.append(sc)
            else:
                skipped.append(sc)
        reason = f"selectors: {', '.join(selectors)}"
    else:
        targets = set(wanted_owasp_ids)
        for sc in suite_def.cases:
            owasp = _infer_case_owasp_id(sc)
            if owasp and owasp in targets:
                selected.append(sc)
            else:
                skipped.append(sc)
        reason = f"OWASP IDs: {', '.join(sorted(targets))}"

    if not selected:
        raise SystemExit(
            "QA calibration slice matched 0 cases. "
            "Either pass --qa-cases (explicit selectors) or ensure case_id/branch/label contains an OWASP id like 'A03'."
        )

    # Deterministic ordering.
    selected.sort(key=lambda sc: str(sc.case.case_id))

    print("\n🧪 QA calibration slice")
    print(f"   - {reason}")
    print(f"   - selected {len(selected)} case(s); skipped {len(skipped)}")

    return SuiteDefinition(
        suite_id=suite_def.suite_id,
        scanners=suite_def.scanners,
        cases=selected,
        analysis=suite_def.analysis,
    )
