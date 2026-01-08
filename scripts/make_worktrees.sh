#!/usr/bin/env bash
set -euo pipefail

# scripts/make_worktrees.sh
#
# Create a local "base" clone + a git worktree checkout for each remote branch.
# This is the most practical way to run a branch-per-case benchmark suite.
#
# Usage:
#   scripts/make_worktrees.sh <repo_url> [base_repo_dir] [worktrees_root] [cases_csv]
#
# Example (Durinn micro-suite):
#   scripts/make_worktrees.sh https://github.com/Chai80/durinn-owasp2021-python-micro-suite.git
#
# After this completes, you can run:
#   python sast_cli.py --mode suite --suite-id owaspTest --scanners semgrep,snyk,sonar \
#     --cases-from suites/<repo_name>_cases.csv

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

REPO_URL="${1:-}"
if [[ -z "${REPO_URL}" ]]; then
  echo "Usage: scripts/make_worktrees.sh <repo_url> [base_repo_dir] [worktrees_root] [cases_csv]" >&2
  exit 2
fi

# Derive a friendly repo name from the URL
REPO_NAME="$(basename "${REPO_URL}")"
REPO_NAME="${REPO_NAME%.git}"

BASE_REPO_DIR="${2:-${ROOT_DIR}/repos/${REPO_NAME}}"
WORKTREES_ROOT="${3:-${ROOT_DIR}/repos/worktrees/${REPO_NAME}}"
CASES_CSV="${4:-${ROOT_DIR}/suites/${REPO_NAME}_cases.csv}"

mkdir -p "$(dirname "${BASE_REPO_DIR}")" "$(dirname "${WORKTREES_ROOT}")" "$(dirname "${CASES_CSV}")"

if [[ ! -d "${BASE_REPO_DIR}/.git" ]]; then
  echo "📥 Cloning base repo into: ${BASE_REPO_DIR}" >&2
  git clone "${REPO_URL}" "${BASE_REPO_DIR}" >&2
else
  echo "✅ Base repo exists: ${BASE_REPO_DIR}" >&2
fi

# Ensure all remote branches are present
( cd "${BASE_REPO_DIR}" && git fetch --all --prune ) >&2

mkdir -p "${WORKTREES_ROOT}"

echo "🔎 Discovering remote branches..." >&2
BRANCHES=()
while IFS= read -r BR; do
  [[ -z "${BR}" ]] && continue
  BRANCHES+=("${BR}")
done < <(
  git -C "${BASE_REPO_DIR}" branch -r \
    | sed 's|^[ *]*||' \
    | grep '^origin/' \
    | grep -v -E 'origin/(HEAD|main|master)$' \
    | sed 's|^origin/||' \
    | sort
)

if [[ "${#BRANCHES[@]}" -eq 0 ]]; then
  echo "❌ No remote branches found under origin/ (other than main/master)." >&2
  exit 1
fi

echo "🌳 Creating worktrees under: ${WORKTREES_ROOT}" >&2
for BR in "${BRANCHES[@]}"; do
  WT_PATH="${WORKTREES_ROOT}/${BR}"
  mkdir -p "$(dirname "${WT_PATH}")"

  # Create local branch tracking origin/<BR> if missing
  if ! git -C "${BASE_REPO_DIR}" show-ref --verify --quiet "refs/heads/${BR}"; then
    # --track fails if it already exists; suppress noise.
    git -C "${BASE_REPO_DIR}" branch --track "${BR}" "origin/${BR}" >/dev/null 2>&1 || true
  fi

  if [[ -e "${WT_PATH}/.git" ]]; then
    echo "  SKIP ${BR} (worktree exists)" >&2
  else
    echo "  ADD  ${BR}" >&2
    git -C "${BASE_REPO_DIR}" worktree add "${WT_PATH}" "${BR}" >/dev/null
  fi
done

echo "🧾 Writing cases CSV: ${CASES_CSV}" >&2
{
  echo "case_id,repo_path,label,branch"
  for BR in "${BRANCHES[@]}"; do
    WT_PATH="${WORKTREES_ROOT}/${BR}"

    # case_id: preserve '/' structure as '__' to avoid collisions
    CASE_ID="${BR//\//__}"
    # Conservative sanitize (close to pipeline.safe_name)
    CASE_ID="$(echo "${CASE_ID}" | sed 's/[^a-zA-Z0-9_.:-]/_/g; s/_\+/_/g; s/^_//; s/_$//')"

    echo "${CASE_ID},${WT_PATH},${BR},${BR}"
  done
} > "${CASES_CSV}"

echo "✅ Done." >&2

echo "" >&2
echo "Next:" >&2
echo "  python sast_cli.py --mode suite --suite-id owaspTest --scanners semgrep,snyk,sonar --cases-from ${CASES_CSV}" >&2
