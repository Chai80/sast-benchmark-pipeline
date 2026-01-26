import ast
import unittest
from pathlib import Path
from typing import Iterable, List, Tuple


REPO_ROOT = Path(__file__).resolve().parents[1]

# Dependency rules (kept intentionally small and explicit):
# - contracts (sast_benchmark/) must not depend on tools/ or pipeline/
# - tools/ must not depend on pipeline/
FORBIDDEN_IMPORTS = {
    "sast_benchmark": ("tools", "pipeline"),
    "tools": ("pipeline",),
}


def iter_py_files(package_dir: Path) -> Iterable[Path]:
    for p in package_dir.rglob("*.py"):
        # Skip cache/hidden dirs if present
        if any(part.startswith(".") for part in p.parts):
            continue
        if "__pycache__" in p.parts:
            continue
        yield p


def find_forbidden_imports(
    py_file: Path, forbidden_roots: Tuple[str, ...]
) -> List[str]:
    src = py_file.read_text(encoding="utf-8", errors="ignore")
    tree = ast.parse(src, filename=str(py_file))

    violations: List[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in forbidden_roots:
                    violations.append(alias.name)

        elif isinstance(node, ast.ImportFrom):
            # Only enforce absolute imports; relative imports are within-package by definition.
            if node.level != 0:
                continue
            if not node.module:
                continue
            root = node.module.split(".", 1)[0]
            if root in forbidden_roots:
                violations.append(node.module)

    return violations


class TestDependencyBoundaries(unittest.TestCase):
    def test_dependency_direction_is_enforced(self) -> None:
        problems: List[str] = []

        for pkg, forbidden in FORBIDDEN_IMPORTS.items():
            pkg_dir = REPO_ROOT / pkg
            if not pkg_dir.exists():
                continue

            for py_file in iter_py_files(pkg_dir):
                bad = find_forbidden_imports(py_file, forbidden)
                if bad:
                    rel = py_file.relative_to(REPO_ROOT)
                    problems.append(f"{rel} imports forbidden modules: {bad}")

        if problems:
            msg = (
                "Forbidden imports detected (violates dependency direction):\n"
                + "\n".join(problems)
            )
            self.fail(msg)
