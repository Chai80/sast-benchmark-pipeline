#!/usr/bin/env bash
set -euo pipefail

PIPE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PIPE_ROOT"

WORKTREES_ROOT="${1:?Usage: $0 <WORKTREES_ROOT> [SUITE_ID]}"
SUITE_ID="${2:-durinn-owasp-sast-$(date -u +"%Y%m%dT%H%M%SZ")}"
SCANNERS="${SCANNERS:-semgrep,snyk,sonar}"

echo "=== PIPE_ROOT      : $PIPE_ROOT"
echo "=== WORKTREES_ROOT : $WORKTREES_ROOT"
echo "=== SUITE_ID       : $SUITE_ID"
echo "=== SCANNERS       : $SCANNERS"
echo

if [[ ! -d "$WORKTREES_ROOT" ]]; then
  echo "ERROR: WORKTREES_ROOT does not exist: $WORKTREES_ROOT"
  exit 2
fi

echo "== Step 1: Refresh worktrees (baseline-clean + owasp2021-a*) to origin/<branch> =="

# Find git worktrees by locating '.git' (file or dir). Depth 3 covers benchmark/sets-and-gt too.
while IFS= read -r -d '' git_marker; do
  repo_dir="$(dirname "$git_marker")"

  # Only refresh top-level baseline-clean and owasp2021-a* folders
  name="$(basename "$repo_dir")"
  if [[ "$name" != baseline-clean && "$name" != owasp2021-a* ]]; then
    continue
  fi

  echo "Updating $name ..."
  git -C "$repo_dir" fetch origin --prune

  if git -C "$repo_dir" rev-parse --verify "origin/$name" >/dev/null 2>&1; then
    git -C "$repo_dir" reset --hard "origin/$name"
  else
    echo "  WARN: origin/$name not found. Leaving HEAD as-is."
  fi

  # Ensure clean working tree (benchmark runs should be clean)
  git -C "$repo_dir" clean -fdx >/dev/null 2>&1 || true

  echo "  HEAD: $(git -C "$repo_dir" rev-parse --short HEAD)"
done < <(find "$WORKTREES_ROOT" -maxdepth 3 -name ".git" -print0)

echo
echo "== Step 2: Verify GT scope is branch-local (10 per OWASP branch; A06=0) =="

python - <<'PY'
import os, re, sys
try:
    import yaml
except Exception as e:
    print("ERROR: PyYAML is required for GT checks. Install with: python -m pip install pyyaml")
    raise

root = sys.argv[1] if len(sys.argv) > 1 else None
if not root or not os.path.isdir(root):
    raise SystemExit("ERROR: bad WORKTREES_ROOT passed to python GT check")

bad = []
branches = sorted([d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))])

for b in branches:
    if not (b == "baseline-clean" or b.startswith("owasp2021-a")):
        continue

    if b == "baseline-clean":
        # baseline is a negative control; we don't require GT
        continue

    m = re.match(r"^owasp2021-a(\d{2})-", b)
    if not m:
        continue

    num = m.group(1)
    expected_ids = set()
    expected_count = 0 if num == "06" else 10
    if expected_count == 10:
        expected_ids = {f"OWASP2021_A{num}_{i:02d}" for i in range(1, 11)}

    gt_path = os.path.join(root, b, "benchmark", "gt_catalog.yaml")
    if not os.path.exists(gt_path):
        bad.append((b, f"missing {gt_path} (need branch-local GT)"))
        continue

    with open(gt_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    items = data.get("items", []) or []
    ids = {it.get("id") for it in items if isinstance(it, dict)}

    if len(items) != expected_count:
        bad.append((b, f"gt_catalog items={len(items)} expected={expected_count} (likely stale/global GT)"))
        continue

    if expected_count == 10 and ids != expected_ids:
        missing = sorted(expected_ids - ids)
        extra = sorted(ids - expected_ids)
        bad.append((b, f"GT IDs mismatch. missing={missing} extra={extra}"))
        continue

print("GT scope checks: PASS" if not bad else "GT scope checks: FAIL")
if bad:
    for b, msg in bad:
        print(f"  - {b}: {msg}")
    raise SystemExit(2)
PY "$WORKTREES_ROOT"

echo
echo "== Step 3: Build deterministic OWASP-only case CSV (A06 marked sca) =="

CSV="/tmp/durinn_owasp_cases_${SUITE_ID}.csv"

python - <<'PY'
import csv, json, os, re, sys

root, out = sys.argv[1], sys.argv[2]

rows = []
# baseline-clean first (optional but useful)
base = os.path.join(root, "baseline-clean")
if os.path.isdir(base):
    rows.append({
        "case_id": "baseline-clean",
        "repo_path": base,
        "label": "baseline-clean",
        "branch": "baseline-clean",
        "track": "sast",
        "tags_json": json.dumps({"kind": "negative_control"})
    })

# OWASP branches
for d in sorted(os.listdir(root)):
    p = os.path.join(root, d)
    if not os.path.isdir(p):
        continue
    if not d.startswith("owasp2021-a"):
        continue
    m = re.match(r"^owasp2021-a(\d{2})-", d)
    if not m:
        continue
    num = m.group(1)
    track = "sca" if num == "06" else "sast"
    rows.append({
        "case_id": d,
        "repo_path": p,
        "label": d,
        "branch": d,
        "track": track,
        "tags_json": json.dumps({"owasp": f"A{num}"})
    })

with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["case_id","repo_path","label","branch","track","tags_json"])
    w.writeheader()
    w.writerows(rows)

print(f"Wrote {out} with {len(rows)} rows")
PY "$WORKTREES_ROOT" "$CSV"

echo
echo "== Step 4: Run suite scan-only (semgrep+snyk+sonar), SAST track only =="

python sast_cli.py \
  --mode suite \
  --suite-id "$SUITE_ID" \
  --scanners "$SCANNERS" \
  --cases-from "$CSV" \
  --track sast \
  --skip-analysis

echo
echo "== Step 5: Post-run sanity check: GT counts inside suite output =="

OUT_DIR="runs/suites/$SUITE_ID"
python - <<'PY'
import glob, os, re, sys
try:
    import yaml
except Exception:
    print("PyYAML missing; skipping post-run GT check")
    raise SystemExit(0)

suite_dir = sys.argv[1]
case_dirs = sorted(glob.glob(os.path.join(suite_dir, "cases", "owasp2021-a*")))
bad = []
for c in case_dirs:
    name = os.path.basename(c)
    m = re.match(r"^owasp2021-a(\d{2})-", name)
    if not m:
        continue
    num = m.group(1)
    expected = 0 if num == "06" else 10
    gt_path = os.path.join(c, "gt", "gt_catalog.yaml")
    if not os.path.exists(gt_path):
        bad.append((name, "missing gt/gt_catalog.yaml in suite output"))
        continue
    data = yaml.safe_load(open(gt_path, "r", encoding="utf-8")) or {}
    items = data.get("items", []) or []
    if len(items) != expected:
        bad.append((name, f"suite gt items={len(items)} expected={expected}"))

if bad:
    print("POST-RUN GT CHECK FAIL:")
    for n, msg in bad:
        print(f"  - {n}: {msg}")
    raise SystemExit(2)
print("POST-RUN GT CHECK PASS")
PY "$OUT_DIR"

echo
echo "DONE. Outputs in: runs/suites/$SUITE_ID/"
