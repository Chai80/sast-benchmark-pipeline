#!/usr/bin/env bash
set -euo pipefail

# scripts/clean_repo_artifacts.sh
#
# Remove common generated artifacts that should never be committed.
#
# This is intentionally conservative: it does NOT delete runs/ or repos/.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "🧹 Cleaning Python bytecode + caches..." >&2

# Python bytecode caches
find . -type d -name "__pycache__" -prune -print -exec rm -rf {} + 2>/dev/null || true
find . -type f \( -name "*.pyc" -o -name "*.pyo" -o -name "*.pyd" \) -print -delete 2>/dev/null || true

# Test / lint caches
rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage 2>/dev/null || true

echo "🧹 Cleaning OS junk..." >&2
find . -type f \( -name ".DS_Store" -o -name "Thumbs.db" \) -print -delete 2>/dev/null || true

echo "🧹 Cleaning known accidental repo-root artifacts..." >&2
rm -f -- firstTestRun 2>/dev/null || true

echo "✅ Done." >&2
