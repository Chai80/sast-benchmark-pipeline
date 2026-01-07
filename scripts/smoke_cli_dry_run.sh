#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[smoke] repo: $ROOT"
echo "[smoke] python: $(python -V 2>&1)"

# 1) Help should render (verifies imports + argparse wiring)
python "$ROOT/sast_cli.py" --help >/dev/null

echo "[smoke] dry-run scan: semgrep (repo-path)"
python "$ROOT/sast_cli.py" \
  --mode scan \
  --scanner semgrep \
  --repo-path "$ROOT" \
  --dry-run \
  --no-suite

echo "[smoke] dry-run benchmark: semgrep+snyk (repo-url)"
python "$ROOT/sast_cli.py" \
  --mode benchmark \
  --scanners semgrep,snyk \
  --repo-url https://github.com/juice-shop/juice-shop.git \
  --dry-run \
  --no-suite

# Sonar requires SONAR_ORG + SONAR_TOKEN even to build args (project key derivation).
# We skip it here so this smoke test can run without secrets.
if [[ -n "${SONAR_ORG:-}" && -n "${SONAR_TOKEN:-}" ]]; then
  echo "[smoke] dry-run benchmark: sonar (env present)"
  python "$ROOT/sast_cli.py" \
    --mode benchmark \
    --scanners sonar \
    --repo-url https://github.com/juice-shop/juice-shop.git \
    --dry-run \
    --no-suite
else
  echo "[smoke] skipping sonar dry-run (SONAR_ORG/SONAR_TOKEN not set)"
fi

echo "[smoke] ok"
