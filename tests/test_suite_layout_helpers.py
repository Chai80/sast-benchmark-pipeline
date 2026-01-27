from __future__ import annotations

from pathlib import Path

import pytest

from pipeline.suites.layout import (
    find_case_dir,
    get_suite_paths,
    resolve_suite_dir,
    resolve_suite_id,
    suite_dir_from_case_dir,
    suite_paths_from_path,
)


def test_resolve_suite_id_latest_uses_pointer_file(tmp_path: Path) -> None:
    suite_root = tmp_path
    suite_id = "20250101010101"

    suite_dir = suite_root / suite_id
    suite_dir.mkdir(parents=True)
    (suite_root / "LATEST").write_text(suite_id)

    assert resolve_suite_id(suite_id="latest", suite_root=suite_root) == suite_id
    assert resolve_suite_dir(suite_id="latest", suite_root=suite_root) == suite_dir.resolve()


def test_resolve_suite_id_latest_falls_back_to_lexicographic_max(tmp_path: Path) -> None:
    suite_root = tmp_path
    (suite_root / "20240101010101").mkdir(parents=True)
    (suite_root / "20250101010101").mkdir(parents=True)

    assert resolve_suite_id(suite_id="latest", suite_root=suite_root) == "20250101010101"


def test_resolve_suite_id_pointer_to_missing_suite_raises(tmp_path: Path) -> None:
    suite_root = tmp_path
    (suite_root / "LATEST").write_text("does_not_exist")

    with pytest.raises(FileNotFoundError):
        resolve_suite_id(suite_id="latest", suite_root=suite_root)


def test_find_case_dir_and_suite_dir_helpers(tmp_path: Path) -> None:
    suite_dir = tmp_path / "suite123"
    case_dir = suite_dir / "cases" / "caseA"
    analysis_dir = case_dir / "analysis"
    (analysis_dir / "_tables").mkdir(parents=True)

    assert find_case_dir(analysis_dir) == case_dir.resolve()
    assert find_case_dir(analysis_dir / "_tables") == case_dir.resolve()
    assert suite_dir_from_case_dir(case_dir) == suite_dir.resolve()

    paths = suite_paths_from_path(analysis_dir)
    assert paths.case_id == "caseA"
    assert paths.suite_id == "suite123"
    assert paths.case_dir == case_dir.resolve()


def test_get_suite_paths_resolves_latest_suite_id(tmp_path: Path) -> None:
    suite_root = tmp_path
    suite_id = "20250101010101"
    (suite_root / suite_id).mkdir(parents=True)
    (suite_root / "LATEST").write_text(suite_id)

    paths = get_suite_paths(case_id="case1", suite_id="latest", suite_root=suite_root)

    assert paths.suite_id == suite_id
    assert paths.suite_dir == (suite_root / suite_id).resolve()
    assert paths.case_dir == (suite_root / suite_id / "cases" / "case1").resolve()
