# Durinn - SAST Benchmark & Normalization Pipeline

Run multiple SAST/security scanners against one or many repos, produce comparable outputs,
and compute cross-tool analysis (agreement/hotspots/taxonomy/triage + optional GT scoring).

## TL;DR
- Produces:
  - **Bronze** = raw tool output (tool-specific)
  - **Silver** = normalized findings (`normalized.json`, schema v1.1)
  - **Gold** = analysis artifacts (tables + packs)
- Primary unit: suite -> cases -> tool runs
- Start here: Quickstart below

## Documentation
- `ARCHITECTURE.md` - system overview + filesystem contracts
- `normalized-schema.md` - `normalized.json` contract
- `docs/SYSTEM_DIAGRAMS.md` - diagrams + stage lists
- `docs/suite_inputs.md` - suite input formats (CSV/worktrees/replay)
- `docs/triage_queue_contract.md` - triage queue schema + tie-break keys
- `docs/triage_calibration.md` - triage calibration + evaluation artifacts

---

## Quickstart (5 minutes)

### 1) Create a venv + install deps

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) Configure env vars (optional)

Create a `.env` in the repo root (only needed for scanners you run).

```bash
# Snyk
SNYK_TOKEN=...

# SonarCloud
SONAR_TOKEN=...
SONAR_ORG=...

# Aikido (only if using aikido)
AIKIDO_CLIENT_ID=...
AIKIDO_CLIENT_SECRET=...
```

### 3) Run one tool (scan mode)

```bash
python sast_cli.py --mode scan --scanner semgrep --repo-key juice_shop
# or
python sast_cli.py --mode scan --scanner semgrep --repo-url https://github.com/juice-shop/juice-shop.git
```

### 4) Run multiple tools (benchmark mode)

```bash
python sast_cli.py --mode benchmark --repo-key juice_shop --scanners semgrep,snyk,sonar
```

### 5) Run a multi-case suite (suite mode)

Option A: discover cases from an existing worktrees folder

```bash
python sast_cli.py --mode suite \
  --worktrees-root repos/worktrees/<your_suite_repo> \
  --scanners semgrep,snyk,sonar
```

Option B: bootstrap worktrees from a repo URL + branches

```bash
python sast_cli.py --mode suite \
  --repo-url https://github.com/Chai80/durinn-calibration-suite-python \
  --branches A03,A07 \
  --scanners semgrep,snyk,sonar
```

### 6) QA calibration runbook (suite mode)

This runs: suite -> build triage_dataset.csv -> build triage_calibration.json -> build triage_eval_summary.json ->
reanalyze so per-case triage_queue.csv picks up calibration -> validate outputs with a PASS/FAIL checklist.

```bash
python sast_cli.py --mode suite \
  --qa-calibration --qa-scope smoke \
  --repo-url https://github.com/Chai80/durinn-calibration-suite-python \
  --scanners semgrep,snyk,sonar \
  --gt-tolerance 10
```

### 7) Re-run analysis on an existing suite

```bash
python sast_cli.py --mode analyze --metric suite --suite-id latest --repo-key juice_shop
```

---

## Key concepts

### Bronze / Silver / Gold
- **Bronze**: raw tool outputs (SARIF/JSON/text), tool-specific
- **Silver**: normalized findings in a stable schema (`normalized.json`)
- **Gold**: analysis outputs (agreement, taxonomy, triage, GT scoring, etc.)

### Suite / Case / Tool run
- A **suite** is one run folder: `runs/suites/<suite_id>/`
- A **case** is one checkout within the suite: `cases/<case_id>/`
- A **tool run** is one tool executed on one case: `tool_runs/<tool>/<run_id>/...`

### `repos/` is an input cache (safe to delete)
`repos/` holds clones/worktrees to avoid re-cloning. It is safe to delete if you want a clean slate.

### `runs/` is output (do not commit)
`runs/` contains scanner outputs and may include sensitive paths and code snippets. Keep it out of git.

---

## Requirements
- Python 3.10+
- git
- Scanner prerequisites:
  - **Semgrep**: invoked as a CLI (installed via `pip install -r requirements.txt`)
  - **Snyk**: `snyk` CLI + `SNYK_TOKEN`
  - **SonarCloud**: `sonar-scanner` + `SONAR_TOKEN` + `SONAR_ORG`
  - **Aikido**: `AIKIDO_CLIENT_ID` + `AIKIDO_CLIENT_SECRET`

---

## CLI overview

### Modes
- `scan` - run one scanner against one repo
- `benchmark` - run multiple scanners against one repo (then runs analysis by default)
- `suite` - run multiple scanners across multiple cases (interactive/CSV/worktrees/replay)
- `analyze` - compute metrics from existing normalized runs

### Common flags
- Repo selection:
  - `--repo-key` / `--repo-url` / `--repo-path`
- Scanner selection:
  - `--scanner` (scan mode)
  - `--scanners` (benchmark/suite)
- Suite inputs (suite mode):
  - `--worktrees-root`
  - `--cases-from` (CSV)
  - `--suite-file` (Python replay file)
  - `--repo-url` + `--branches` (bootstrap worktrees)
- Analysis knobs:
  - `--tolerance` (location clustering)
  - `--gt-tolerance` and `--gt-source` (GT scoring)
  - `--analysis-filter` (security|all)

Help:

```bash
python sast_cli.py --help
python sast_cli.py --mode suite --help
python sast_cli.py --mode analyze --help
```

---

## Outputs (where to look)

### Suite layout (preferred)

Suite root:
- `runs/suites/<suite_id>/summary.csv` - one row per case
- `runs/suites/<suite_id>/suite.json` - suite manifest / traceability

Per-case:
- `runs/suites/<suite_id>/cases/<case_id>/case.json` - case manifest
- `.../tool_runs/<tool>/<run_id>/run.json` + `metadata.json`
- `.../tool_runs/<tool>/<run_id>/raw.*` + `normalized.json`

Per-case analysis outputs:
- Final JSON packs typically remain in `analysis/`
- **CSV tables are organized under `analysis/_tables/`**
  - Example: `.../analysis/_tables/triage_queue.csv`
- Debug/intermediate artifacts and logs are organized under `analysis/_checkpoints/`

Suite-level triage calibration artifacts (when using `--qa-calibration`):
- `runs/suites/<suite_id>/analysis/_tables/triage_dataset.csv`
- `runs/suites/<suite_id>/analysis/triage_calibration.json`
- `runs/suites/<suite_id>/analysis/_tables/triage_calibration_report.csv`
- `runs/suites/<suite_id>/analysis/_tables/triage_eval_summary.json`
- `runs/suites/<suite_id>/analysis/qa_calibration_checklist.txt`
- `runs/suites/<suite_id>/analysis/qa_manifest.json` - QA runbook manifest ("receipt" for inputs + selected GT tolerance + artifact paths)
  - Legacy alias: `analysis/qa_calibration_manifest.json`

Optional GT tolerance sweep artifacts (when using `--gt-tolerance-sweep` / `--gt-tolerance-auto`):
- `runs/suites/<suite_id>/analysis/_tables/gt_tolerance_sweep_report.csv`
- `runs/suites/<suite_id>/analysis/_tables/gt_tolerance_sweep_tool_stats.csv`
- `runs/suites/<suite_id>/analysis/gt_tolerance_sweep.json`
- `runs/suites/<suite_id>/analysis/gt_tolerance_selection.json`
- snapshots under `runs/suites/<suite_id>/analysis/_sweeps/gt_tol_<t>/analysis/...`

**What is `qa_manifest.json`?**

`qa_manifest.json` is a small, deterministic "receipt" for a QA calibration run. It records:

- the **inputs/policy** used (including GT tolerance policy: explicit vs sweep vs auto-select)
- the **effective** `gt_tolerance` that was actually applied
- the **canonical paths** to the artifacts produced (dataset, calibration, eval summary, checklist, sweep reports)

This makes CI runs auditable (no silent skips) and makes debugging diffs much faster:
you can answer “what changed?” by comparing two manifests instead of hunting through logs.

Note: for backward compatibility the pipeline also writes the same payload to
`runs/suites/<suite_id>/analysis/qa_calibration_manifest.json`.

### "Latest suite" pointer
`runs/suites/LATEST` is a small file containing the most recent suite id.

If you run the **QA calibration runbook** ("--qa-calibration"), the pipeline also writes:

- `runs/suites/LATEST_QA` — the most recent **QA calibration** suite id

QA suites are additionally tagged in `runs/suites/<suite_id>/suite.json` with:

- `"suite_kind": "qa_calibration"` (regular suites default to `"benchmark"`)

In CLI analyze mode you can use:

```bash
python sast_cli.py --mode analyze --metric suite --suite-id latest --repo-key juice_shop
```

In shell scripts:

```bash
SUITE=$(cat runs/suites/LATEST)
echo "$SUITE"
```

### Suite compare (drift report)
To answer "what changed between two suite runs?" you can generate a deterministic
suite-to-suite comparison report.

This reads existing artifacts (no scans) and writes:

- `runs/suites/<suite_a>/analysis/_tables/suite_compare_report.csv`
- `runs/suites/<suite_a>/analysis/_tables/suite_compare_report.json`

Examples:

```bash
# Default (and recommended): compare latest vs previous
python sast_cli.py --mode analyze --metric suite_compare --compare-latest-previous

# Compare latest vs a specific suite id
python sast_cli.py --mode analyze --metric suite_compare --compare-latest-to 20260101T000000Z

# Compare two explicit suites
python sast_cli.py --mode analyze --metric suite_compare --compare-suites 20260101T000000Z,20260105T000000Z

# Compare latest QA calibration vs previous QA calibration
python sast_cli.py --mode analyze --metric suite_compare --compare-suites latestqa,previousqa
```

Notes:
- This requires both suites to have `analysis/_tables/triage_eval_summary.json`.
- If a suite was produced by the QA runbook, the report also compares `analysis/qa_manifest.json` inputs.

### Legacy layout (when `--no-suite`)
If you disable suite layout, outputs go under `runs/<tool>/...` instead.
See `ARCHITECTURE.md` for the full directory trees.

---

## Debugging and troubleshooting

- If a scan failed, inspect the tool run folder:
  - `.../tool_runs/<tool>/<run_id>/run.json` (exit code + stderr snippet)
  - `.../tool_runs/<tool>/<run_id>/raw.*` (tool-specific output)
- If `normalized.json` is missing:
  - the tool likely failed, or produced an unsupported output format
- If you cannot find CSVs:
  - check `analysis/_tables/` (the pipeline reorganizes outputs after analysis)

---

## Advanced usage

### Build worktrees from a repo with many branches

```bash
scripts/make_worktrees.sh https://github.com/Chai80/durinn-owasp2021-python-micro-suite.git
python sast_cli.py --mode suite \
  --worktrees-root repos/worktrees/durinn-owasp2021-python-micro-suite \
  --scanners semgrep,snyk,sonar
```

### Suite inputs from CSV
See examples under `examples/suite_inputs/`.

Expected columns:
- `case_id`
- `repo_path`
- optional: `label`, `branch`, `track`, `tags_json`

### Replay files (`--suite-file`)
`--suite-file` points to an optional Python replay file (exports `SUITE_RAW` or `SUITE_DEF`).

Think of this as a replay button for suites you built interactively: it captures the curated
case list and scanners so you can rerun later without re-answering prompts.

By default, interactive suite runs save replay artifacts under:
`runs/suites/<suite_id>/replay/`.

If you built a suite from `--worktrees-root` or `--cases-from`, you usually do not need a replay
file because the command itself is already replayable.

### Export a suite summary CSV (script)
There is no `--mode export` in the CLI. Use the helper script instead:

```bash
python scripts/export_suite_summary.py \
  --suite-dir runs/suites/<suite_id> \
  --out /tmp/suite_summary.csv
```

---

## Extending the repo (for contributors)

### Add a new scanner
- Create `tools/scan_<tool>.py` entrypoint
- Implement `tools/<tool>/runner.py` + `normalize.py`
- Register the scanner in `pipeline/scanners.py`
- Required artifacts: raw + normalized + metadata + run.json

### Add a new analysis stage
- Add stage under `pipeline/analysis/stages/`
- Register stage + update the stage list in `pipeline/analysis/framework/pipelines.py`

---

## Development

Run tests:

```bash
pytest -q
```

Repo hygiene:
- Do not commit `repos/`, `runs/`, or `.env`

---

## Security notes
- Treat scanner outputs as sensitive (paths, code snippets, tokens in logs)
- Avoid uploading `runs/` artifacts unless sanitized
