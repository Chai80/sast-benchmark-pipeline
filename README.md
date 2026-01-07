# SAST Benchmark & Normalization Pipeline

This repo runs multiple security scanners (Semgrep, SonarCloud/SonarScanner, Snyk Code, Aikido) against a target repository and writes **comparable outputs** per tool:

- Raw tool output (tool-specific format, saved per run)
- Normalized output (`normalized.json`) using the contract in `normalized-schema.md`
- `metadata.json` (tool version, commit SHA, command, timings, etc.)
- `run.json` (a small pointer/manifest file designed for DB ingestion)

## Documentation

- **Architecture:** `ARCHITECTURE.md`
- **Normalized output contract:** `normalized-schema.md`

## Concepts (how to think about runs)

This pipeline supports two output styles:

### Suite layout (preferred, DB/ETL-friendly)

A **suite** is one experiment run (timestamped), and a **case** is one scan target inside the suite (e.g., a branch/worktree checkout or one repository state).

Within a case, each scanner produces a **tool run** (one tool × one case × one run_id).

### Legacy layout (still supported)

You can disable suite layout and write directly to `runs/<tool>/...` for quick one-off scans.

## Requirements

### General

- Python **3.10+**
- `git` available on your `PATH`

### Python dependencies

Install the Python dependencies from `requirements.txt`:

```bash
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
```

Windows (PowerShell):

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> Note: `requirements.txt` covers the pipeline + shared utilities and includes Semgrep as a Python-installed CLI.  
> Snyk and Sonar require **separate external CLIs** (see below).

## Tool prerequisites

### Semgrep
- Installed via `pip install -r requirements.txt` (or `pip install semgrep`).

### Snyk Code
- Install the **Snyk CLI** (external dependency).
  - Example (npm): `npm install -g snyk`
- Provide a token via env var: `SNYK_TOKEN`
  - If you run `sast_cli.py`, it will load a project-root `.env` file automatically (if present).
  - If you run `tools/scan_snyk.py` directly, export `SNYK_TOKEN` in your shell.

### SonarCloud / SonarScanner
- Java **17+**
- `sonar-scanner` installed and available on `PATH`
- SonarCloud org + token
  - Required env vars: `SONAR_ORG`, `SONAR_TOKEN`
  - Optional: `SONAR_HOST` (defaults to `https://sonarcloud.io` in most setups)

### Aikido
- Aikido workspace + Public REST API credentials
  - Required env vars: `AIKIDO_CLIENT_ID`, `AIKIDO_CLIENT_SECRET`

## Configuration

### Environment variables (`.env`)

Create a `.env` file in the repo root **or** export variables in your shell.

Example `.env`:

```dotenv
# Aikido
AIKIDO_CLIENT_ID=
AIKIDO_CLIENT_SECRET=

# SonarCloud
SONAR_ORG=
SONAR_TOKEN=
SONAR_HOST=https://sonarcloud.io

# Snyk
SNYK_TOKEN=
```

`python sast_cli.py` automatically loads `.env` if present.

## Quickstart

### 1) Run a single scanner (scan mode)

```bash
python sast_cli.py --mode scan --scanner semgrep --repo-key juice_shop
```

Scan any repo by URL:

```bash
python sast_cli.py --mode scan --scanner semgrep --repo-url https://github.com/juice-shop/juice-shop.git
```

### 2) Run multiple scanners (benchmark mode)

```bash
python sast_cli.py --mode benchmark --repo-key juice_shop --scanners semgrep,snyk,sonar,aikido
```

If you want to control the suite id (useful in CI):

```bash
python sast_cli.py --mode benchmark --repo-key juice_shop --suite-id 20260107T120000Z
```

### 2b) Run a multi-case suite (suite mode, optional YAML)

Use **suite mode** when you want to run the same scanner set across **many cases**
(e.g., multiple repos, or multiple branch/worktree checkouts) and keep everything
grouped under one `suite_id`.

YAML is **optional**:

- If you pass `--suite-file`, the suite cases + defaults come from YAML.
- If you omit it, the CLI will prompt you interactively and (optionally) write
  a YAML definition you can rerun later.

Run from a YAML suite definition:

```bash
python sast_cli.py --mode suite --suite-file suites/example_suite.yaml
```

Minimal YAML format:

```yaml
suite_id: 20260107T120000Z  # optional
scanners: [semgrep, snyk, sonar]
analysis:
  skip: false
  tolerance: 3
  filter: security
cases:
  - case_id: juice_shop
    repo_key: juice_shop
  - case_id: webgoat
    repo_url: https://github.com/WebGoat/WebGoat.git
```

Note: when `--suite-file` is used, we copy it into the suite output folder as
`runs/suites/<suite_id>/suite_input.yaml` for provenance.

### 3) Analyze the latest suite case (suite metric)

```bash
python sast_cli.py --mode analyze --metric suite --repo-key juice_shop --suite-id latest
```

### 4) Legacy behavior (write directly to runs/<tool>/...)

```bash
python sast_cli.py --mode benchmark --repo-key juice_shop --scanners semgrep,snyk,sonar --no-suite
```

## Running scanners directly (bypassing `sast_cli.py`)

You can run each tool entrypoint directly. These scripts are the stable integration contract used by the pipeline:

- `tools/scan_semgrep.py`
- `tools/scan_snyk.py`
- `tools/scan_sonar.py`
- `tools/scan_aikido.py`

### Semgrep

```bash
python tools/scan_semgrep.py \
  --repo-url https://github.com/juice-shop/juice-shop.git \
  --config p/security-audit \
  --output-root runs/semgrep
```

### Snyk

```bash
python tools/scan_snyk.py \
  --repo-url https://github.com/juice-shop/juice-shop.git \
  --output-root runs/snyk
```

### SonarCloud

Run scan + fetch issues:

```bash
python tools/scan_sonar.py \
  --repo-url https://github.com/juice-shop/juice-shop.git \
  --project-key <your_sonar_project_key> \
  --output-root runs/sonar
```

Fetch issues from an existing SonarCloud project without running a new scan:

```bash
python tools/scan_sonar.py \
  --repo-url https://github.com/juice-shop/juice-shop.git \
  --project-key <your_sonar_project_key> \
  --skip-scan \
  --output-root runs/sonar
```

### Aikido

```bash
python tools/scan_aikido.py \
  --git-ref <owner>/<repo> \
  --output-root runs/aikido
```

## Outputs

### Suite layout (v2, preferred)

When using suite layout (default), results are written under `runs/suites/`:

```text
runs/
  suites/
    LATEST                         # pointer to most recent suite_id
    <suite_id>/
      README.txt
      suite.json                   # suite index (cases, timestamps)
      summary.csv                  # one row per case
      cases/
        <case_id>/
          case.json                # per-case manifest (what ran)
          tool_runs/
            semgrep/<run_id>/
              run.json
              normalized.json
              raw.json
              metadata.json
            snyk/<run_id>/
              run.json
              normalized.json
              raw.sarif
              metadata.json
            sonar/<run_id>/
              run.json
              normalized.json
              raw.json
              metadata.json
              logs/sonar_scan.log
            aikido/<run_id>/
              run.json
              normalized.json
              raw.json
              metadata.json
          analysis/                # cross-tool metrics (suite metric)
            ...
          gt/                      # GT-based scoring outputs (if run)
            gt_score.json
            gt_score.csv
```

### Legacy layout (v1, still supported)

If you pass `--no-suite`, or you call `tools/scan_*.py` directly with `--output-root runs/<tool>`, outputs use the legacy layout:

```text
runs/<tool>/<repo_name>/<run_id>/
  <repo_name>.normalized.json
  <repo_name>.json | <repo_name>.sarif
  metadata.json
```

## Run IDs

Each per-tool run directory id is `YYYYMMDDNN` (date + counter for that day).

Suite ids are UTC timestamps like `YYYYMMDDTHHMMSSZ` (example: `20260107T120000Z`).

## DB ingestion / ETL notes

The suite layout is designed so ingestion does **not** depend on parsing directory names:

- `suite.json` summarizes the suite and points to each case
- `case.json` summarizes the case and points to each tool run
- Each tool run directory contains `run.json` with:
  - `suite_id`, `case_id`, `tool`, `run_id`
  - and the artifact filenames next to it (`normalized.json`, `raw.*`, `metadata.json`, logs)

A simple ingester can:
1) read `suite.json` → suites table
2) read each `case.json` → cases table
3) read each `run.json` → tool_runs table
4) explode `normalized.json.findings[]` → findings table

## Repo hygiene

- `repos/` and `runs/` are generated. Do not commit them.
- Do not commit IDE folders like `.idea/`
- Never commit `.env` (tokens/secrets). If you add an `.env.example`, commit that instead.

## Developer notes (CLI refactor prep)

Before making large changes to the CLI UX, keep a snapshot of the current interface and verify that basic codepaths still work.

- `docs/cli_help_before_refactor.txt` is the baseline output of `python sast_cli.py --help`.
- `scripts/smoke_cli_dry_run.sh` exercises dry-run scan/benchmark codepaths without requiring any API tokens.

Run:

```bash
bash scripts/smoke_cli_dry_run.sh
```
