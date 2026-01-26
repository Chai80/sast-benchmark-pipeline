from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, TypeVar

from sast_benchmark.io.fs import write_csv_atomic, write_json_atomic, write_text_atomic

_TRow = Mapping[str, Any]
_TKey = TypeVar("_TKey")


def write_json(path: Path, data: Any, *, indent: int = 2) -> Path:
    """Write JSON analysis artifacts.

    This is a thin wrapper over :func:`sast_benchmark.io.fs.write_json_atomic`.
    Returning the written path keeps existing call sites unchanged.
    """

    p = Path(path)
    write_json_atomic(p, data, indent=indent, sort_keys=True, ensure_ascii=False)
    return p


def write_csv(
    path: Path,
    rows: Iterable[Dict[str, Any]],
    *,
    fieldnames: Optional[Sequence[str]] = None,
) -> Path:
    """Write CSV analysis artifacts.

    This is a thin wrapper over :func:`sast_benchmark.io.fs.write_csv_atomic`.
    Returning the written path keeps existing call sites unchanged.
    """

    p = Path(path)
    write_csv_atomic(p, rows, fieldnames=fieldnames)
    return p


def write_text(path: Path, text: str, *, encoding: str = "utf-8") -> Path:
    """Write UTF-8 text artifacts atomically.

    Notes
    -----
    This wrapper exists to keep artifact writes consistent across the codebase.
    Prefer it over ``Path.write_text`` when writing pipeline outputs.
    """

    p = Path(path)
    write_text_atomic(p, text, encoding=encoding)
    return p


def write_markdown(path: Path, text: str, *, encoding: str = "utf-8") -> Path:
    """Write a markdown artifact (UTF-8 text).

    This is an alias for :func:`write_text` to keep call sites semantically clear.
    """

    return write_text(Path(path), text, encoding=encoding)


def write_csv_table(
    path: Path,
    rows: Iterable[_TRow],
    *,
    fieldnames: Optional[Sequence[str]] = None,
    sort_key: Optional[Callable[[_TRow], _TKey]] = None,
) -> Path:
    """Write a CSV table with optional stable sorting.

    Parameters
    ----------
    path:
        Output CSV path.
    rows:
        Rows to write (mapping-like objects).
    fieldnames:
        Optional fieldname order.
    sort_key:
        Optional sort key applied *before* writing. This helps keep diffs stable
        without duplicating sorting boilerplate at call sites.

    Notes
    -----
    ``write_csv_atomic`` already materializes rows internally; this wrapper
    materializes once so sorting can be applied.
    """

    rows_list: List[Dict[str, Any]] = [dict(r) for r in rows]
    if sort_key is not None:
        rows_list.sort(key=sort_key)
    return write_csv(Path(path), rows_list, fieldnames=fieldnames)
