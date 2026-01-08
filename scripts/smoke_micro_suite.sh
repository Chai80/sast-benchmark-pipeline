#!/usr/bin/env bash
set -euo pipefail

# scripts/smoke_micro_suite.sh
#
# Quick smoke test for a branch-per-case micro-suite in "suite" mode.
#
# This script:
#   1) picks a few worktree cases from repos/worktrees/<repo_name>/
#   2) runs suite mode with whatever scanners are configured in your env
#   3) checks that normalized.json + analysis outputs exist
#
# Usage:
#   scripts/smoke_micro_suite.sh [repo_name]
#
# Default repo_name:
#   durinn-owasp2021-python-micro-suite

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_NAME="${1:-durinn-owasp2021-python-micro-suite}"
WORKTREES_ROOT="${ROOT_DIR}/repos/worktrees/${REPO_NAME}"

if [[ ! -d "${WORKTREES_ROOT}" ]]; then
  echo "❌ Worktrees root not found: ${WORKTREES_ROOT}" >&2
  echo "   Run scripts/make_worktrees.sh first, e.g.:" >&2
  echo "     scripts/make_worktrees.sh https://github.com/Chai80/${REPO_NAME}.git" >&2
  exit 2
fi

# Pick scanners (gate on env vars so the smoke test is usable everywhere).
SCANNERS=("semgrep")
if [[ -n "${SNYK_TOKEN:-}" ]]; then
  SCANNERS+=("snyk")
else
  echo "ℹ️  SNYK_TOKEN not set -> skipping snyk" >&2
fi
if [[ -n "${SONAR_TOKEN:-}" && -n "${SONAR_ORG:-}" ]]; then
  SCANNERS+=("sonar")
else
  echo "ℹ️  SONAR_TOKEN/SONAR_ORG not set -> skipping sonar" >&2
fi

SCANNERS_CSV="$(IFS=,; echo "${SCANNERS[*]}")"

# Preferred cases (if they exist). Fall back to first 3 discovered.
PREFERRED=(
  "baseline-clean"
  "owasp2021-a03-injection"
  "owasp2021-a05-security-misconfiguration"
)

CASES=()
for br in "${PREFERRED[@]}"; do
  if [[ -e "${WORKTREES_ROOT}/${br}/.git" ]]; then
    CASES+=("${br}")
  fi
  if [[ "${#CASES[@]}" -ge 3 ]]; then
    break
  fi
done

if [[ "${#CASES[@]}" -lt 3 ]]; then
  # Discover checkout dirs by finding '.git' entries and taking parent dirs.
  while IFS= read -r git_entry; do
    repo_dir="$(dirname "${git_entry}")"
    rel="${repo_dir#${WORKTREES_ROOT}/}"
    # Skip weird paths
    if [[ -z "${rel}" || "${rel}" == "${repo_dir}" ]]; then
      continue
    fi
    CASES+=("${rel}")
    if [[ "${#CASES[@]}" -ge 3 ]]; then
      break
    fi
  done < <(find "${WORKTREES_ROOT}" -maxdepth 4 -name .git -print | sort)
fi

if [[ "${#CASES[@]}" -eq 0 ]]; then
  echo "❌ No git worktrees found under ${WORKTREES_ROOT}" >&2
  exit 1
fi

TMP_CSV="$(mktemp "${TMPDIR:-/tmp}/micro_suite_cases.XXXXXX")"
{
  echo "case_id,repo_path,label,branch"
  for br in "${CASES[@]}"; do
    # Match the CLI's case_id behavior: '/' -> '__' then sanitize.
    case_id="${br//\//__}"
    case_id="$(echo "${case_id}" | sed 's/[^a-zA-Z0-9_.:-]/_/g; s/_\+/_/g; s/^_//; s/_$//')"
    echo "${case_id},${WORKTREES_ROOT}/${br},${br},${br}"
  done
} > "${TMP_CSV}"

SUITE_ID="micro-smoke-$(date -u +%Y%m%dT%H%M%SZ)"

echo "🚀 Running smoke suite: ${SUITE_ID}" >&2
echo "   Scanners : ${SCANNERS_CSV}" >&2
echo "   Cases    : ${CASES[*]}" >&2

echo "" >&2
python "${ROOT_DIR}/sast_cli.py" \
  --mode suite \
  --suite-id "${SUITE_ID}" \
  --scanners "${SCANNERS_CSV}" \
  --cases-from "${TMP_CSV}"

SUITE_DIR="${ROOT_DIR}/runs/suites/${SUITE_ID}"

if [[ ! -d "${SUITE_DIR}" ]]; then
  echo "❌ Expected suite dir not found: ${SUITE_DIR}" >&2
  exit 1
fi

echo "" >&2
echo "🔎 Verifying outputs under: ${SUITE_DIR}" >&2

missing=0
for br in "${CASES[@]}"; do
  case_id="${br//\//__}"
  case_id="$(echo "${case_id}" | sed 's/[^a-zA-Z0-9_.:-]/_/g; s/_\+/_/g; s/^_//; s/_$//')"

  case_dir="${SUITE_DIR}/cases/${case_id}"
  if [[ ! -d "${case_dir}" ]]; then
    echo "  ❌ missing case dir: ${case_dir}" >&2
    missing=1
    continue
  fi

  if [[ ! -d "${case_dir}/analysis" ]]; then
    echo "  ❌ missing analysis dir: ${case_dir}/analysis" >&2
    missing=1
  fi

  for tool in "${SCANNERS[@]}"; do
    found="$(find "${case_dir}/tool_runs/${tool}" -type f -name normalized.json 2>/dev/null | head -n 1 || true)"
    if [[ -z "${found}" ]]; then
      echo "  ❌ missing normalized.json for ${case_id}/${tool}" >&2
      missing=1
    fi
  done

done

rm -f "${TMP_CSV}" >/dev/null 2>&1 || true

if [[ "${missing}" -ne 0 ]]; then
  echo "❌ Smoke suite failed checks." >&2
  exit 1
fi

echo "✅ Smoke suite looks good." >&2
