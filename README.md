# Durinn — Deterministic SAST Benchmarking, Normalization & Triage

Durinn is a **filesystem-first benchmarking pipeline** for static/security scanners:
it runs one or more scanners on the same codebase(s), normalizes results into a common contract,
clusters related findings into reviewable issues, and writes analysis artifacts (agreement/hotspots/taxonomy/triage).
It also supports an optional **QA calibration runbook** that learns simple per-tool trust weights from ground truth (GT)
and evaluates top‑K triage quality.

> Core idea: **clusters are the unit of review** (one underlying issue), not raw alert counts.

---

## What this repo demonstrates (hiring-manager signal)

- **Reproducible runs**: one run folder per experiment (`runs/suites/<suite_id>/`) with pinned manifests (`suite.json`, `case.json`, `run.json`)
- **Tool-agnostic normalization**: scanner outputs → `normalized.json` (stable schema, consumed by analysis)
- **Deduplication + provenance**: cluster many findings into one issue while retaining “which tools saw this”
- **Deterministic analysis outputs**: consistent tables/packs under `analysis/` and `analysis/_tables/`
- **Drift attribution**: compare suites deterministically (no rescans) via `--metric suite_compare`
- **QA runbook** (optional): build calibration artifacts, rescore queues, and validate output expectations

---

## Quickstart (local)

### 1) Create a venv + install deps

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

This project is **tested in CI on Python 3.12** (recommended).

### 2) Run a minimal “it works” benchmark (Semgrep only)

This runs the scanner, writes a suite folder, and then runs the analysis suite.

```bash
python sast_cli.py --mode benchmark --repo-key juice_shop --scanners semgrep
```

### 3) Find outputs

Look under:

- `runs/suites/<suite_id>/suite.json` (pinned suite inputs)
- `runs/suites/<suite_id>/summary.csv` (one row per case)
- `runs/suites/<suite_id>/cases/<case_id>/tool_runs/<tool>/<run_id>/normalized.json`
- `runs/suites/<suite_id>/cases/<case_id>/analysis/_tables/triage_queue.csv` (**review queue**)

Tip: `runs/suites/LATEST` points to the most recent suite id.

---

## Supported scanners (current)

Durinn currently wires these scanner integrations:

- `semgrep` (installed via `pip install -r requirements.txt`)
- `snyk` (requires `snyk` CLI + `SNYK_TOKEN`)
- `sonar` (SonarCloud; requires `sonar-scanner` + `SONAR_ORG` + `SONAR_TOKEN`)
- `aikido` (requires `AIKIDO_CLIENT_ID` + `AIKIDO_CLIENT_SECRET`)

Optional: create a `.env` in the repo root for tokens (loaded automatically).

Example `.env`:

```bash
# Snyk
SNYK_TOKEN=...

# SonarCloud
SONAR_ORG=...
SONAR_TOKEN=...

# Aikido
AIKIDO_CLIENT_ID=...
AIKIDO_CLIENT_SECRET=...
```

---

## CLI modes (up to date)

Durinn’s CLI is `sast_cli.py` and currently supports these modes:

- `scan` — run **one** scanner on **one** repo (scan only; does not run analysis)
- `benchmark` — run **multiple** scanners on **one** repo (runs analysis unless `--skip-analysis`)
- `suite` — run scanners across **many cases** (interactive, CSV, worktrees, or replay file)
- `analyze` — compute metrics from existing run artifacts (no rescans)
- `import` — import legacy `runs/<tool>/...` outputs into suite layout

Help:

```bash
python sast_cli.py --help
python sast_cli.py --mode suite --help
python sast_cli.py --mode analyze --help
```

### Common repo selection flags

- `--repo-key` (preset): `juice_shop`, `webgoat`, `dvwa`, `owasp_benchmark`
- `--repo-url` (custom git URL)
- `--repo-path` (local checkout; skip clone)

---

## Typical workflows

### Scan a repo with a single tool (no analysis)

```bash
python sast_cli.py --mode scan --scanner semgrep --repo-key juice_shop
```

### Benchmark multiple tools on one repo (runs analysis by default)

```bash
python sast_cli.py --mode benchmark --repo-key juice_shop --scanners semgrep,snyk,sonar
```

Skip analysis if you only want raw + normalized:

```bash
python sast_cli.py --mode benchmark --repo-key juice_shop --scanners semgrep --skip-analysis
```

### Analyze an existing suite (no rescans)

Compute suite artifacts (defaults to LATEST if `--suite-id` omitted):

```bash
python sast_cli.py --mode analyze --metric suite --suite-id latest
```

Drift report (suite-to-suite compare):

```bash
python sast_cli.py --mode analyze --metric suite_compare --compare-latest-previous
```

### Multi-case suite mode (CSV/worktrees/replay)

Worktrees:

```bash
python sast_cli.py --mode suite   --worktrees-root repos/worktrees/<your_suite_repo>   --scanners semgrep,snyk,sonar
```

From CSV (schema documented in `docs/suite_inputs.md`):

```bash
python sast_cli.py --mode suite   --cases-from /path/to/cases.csv   --scanners semgrep,snyk,sonar
```

Replay (usually generated under `runs/suites/<suite_id>/replay/` for interactive suites):

```bash
python sast_cli.py --mode suite   --suite-file runs/suites/<suite_id>/replay/replay_suite.py
```

### QA calibration runbook (suite mode, optional)

Runs: suite → triage_dataset → triage_calibration → eval summary → (optional) re-analyze per-case queues → PASS/FAIL checklist.

```bash
python sast_cli.py --mode suite   --qa-calibration --qa-scope smoke   --repo-url https://github.com/Chai80/durinn-calibration-suite-python   --scanners semgrep,snyk,sonar   --gt-tolerance 10
```

---

## Outputs (minimal map)

Durinn writes outputs under `runs/` (do not commit; may contain sensitive paths/snippets).

Preferred suite layout:

```text
runs/suites/<suite_id>/
  suite.json
  summary.csv
  cases/<case_id>/
    case.json
    tool_runs/<tool>/<run_id>/
      run.json
      raw.*
      normalized.json
      metadata.json
      logs/...
    analysis/
      _tables/
        triage_queue.csv
```

For the full contract and directory trees, see `ARCHITECTURE.md`.

---

## Documentation map (current repo)

- `ARCHITECTURE.md` — system overview + filesystem contracts (start here)
- `GeneralSystemArchitecture.md` — rationale / boundary narrative
- `normalized-schema.md` — `normalized.json` contract
- `docs/suite_inputs.md` — suite input formats (CSV/worktrees/replay)
- `docs/triage_queue_contract.md` — triage queue schema + tie-break keys
- `docs/triage_calibration.md` — calibration + evaluation artifacts
- `docs/GT_COMPILATION.md` — how GT is compiled/materialized into `gt_catalog.yaml`
- `docs/analytics_mart.md` — optional analytics outputs

Repo root also includes diagrams (e.g., `componentDiagram.png`).

---

## Development

Run tests:

```bash
pytest -q
```

Format + lint:

```bash
pip install -r requirements-dev.txt
ruff format .
ruff check .
```

---

## Security notes

- Treat scanner outputs as sensitive (file paths, code snippets, logs).
- Do not commit `runs/`, `repos/`, or `.env` (they are gitignored).
