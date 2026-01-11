from __future__ import annotations

import re
from typing import Dict, List, Optional


def choose_from_menu(title: str, options: Dict[str, object]) -> str:
    """Show a 1..N menu of keys in 'options' and return the chosen key."""
    keys = list(options.keys())
    print("\n" + title)
    for idx, key in enumerate(keys, start=1):
        val = options[key]
        if isinstance(val, dict) and "label" in val:
            label = str(val["label"])
        else:
            label = str(val)
        print(f"[{idx}] {label} ({key})")

    while True:
        choice = input(f"Enter number (1-{len(keys)}) or Z to exit: ").strip()
        if not choice:
            print("Please enter a number or Z to exit.")
            continue
        if choice.upper() == "Z":
            print("Exiting (Z selected).")
            raise SystemExit(0)
        if choice.isdigit():
            n = int(choice)
            if 1 <= n <= len(keys):
                return keys[n - 1]
        print(f"Invalid choice. Please enter 1-{len(keys)} or Z.")


def _prompt_text(prompt: str, default: Optional[str] = None) -> str:
    """Prompt for free-text input with an optional default."""
    if default is not None:
        raw = input(f"{prompt} [{default}]: ").strip()
        return raw or str(default)
    return input(f"{prompt}: ").strip()


def _prompt_yes_no(prompt: str, *, default: bool = False) -> bool:
    """Prompt for a yes/no question."""
    suffix = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{prompt} ({suffix}): ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes"}:
            return True
        if raw in {"n", "no"}:
            return False
        print("Please enter y or n.")


def _parse_index_selection(raw: str, *, n: int) -> List[int]:
    """Parse a user selection like: 'all' or '1,3-5' into 0-based indices."""
    s = (raw or "").strip().lower()
    if not s:
        return []
    if s in {"all", "*"}:
        return list(range(n))

    out: set[int] = set()
    parts = re.split(r"[\s,]+", s)
    for part in parts:
        if not part:
            continue
        if part in {"z", "quit", "exit"}:
            raise SystemExit(0)
        if "-" in part:
            a, b = part.split("-", 1)
            if a.isdigit() and b.isdigit():
                lo, hi = int(a), int(b)
                if lo > hi:
                    lo, hi = hi, lo
                for k in range(lo, hi + 1):
                    if 1 <= k <= n:
                        out.add(k - 1)
            continue
        if part.isdigit():
            k = int(part)
            if 1 <= k <= n:
                out.add(k - 1)
            continue

    return sorted(out)
