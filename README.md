# SAST Benchmark & Normalization Pipeline

This repo runs multiple SAST scanners (Semgrep, SonarCloud/SonarScanner, Snyk Code, Aikido) against a target repository and writes **comparable JSON outputs** per tool:

- Raw tool output (tool-specific format, saved per run)
- Normalized output (`<repo>.normalized.json`) using the contract in `normalized-schema.md`
- `metadata.json` (tool version, commit SHA, command, timings, etc.)

## Documentation

- **Architecture (Option B packaging):** `ARCHITECTURE.md`
- **Normalized output contract:** `normalized-schema.md`

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

### 1) Run a single scan (recommended entrypoint)

```bash
python sast_cli.py --mode scan --scanner semgrep --repo-key juice_shop
```

You can also scan any repo by URL:

```bash
python sast_cli.py --mode scan --scanner semgrep --repo-url https://github.com/juice-shop/juice-shop.git
```

### 2) Run multiple scanners (benchmark mode)

```bash
python sast_cli.py --mode benchmark --repo-key juice_shop --scanners semgrep,snyk,sonar,aikido
```

### 3) Analyze existing normalized results

Currently supported metric: `hotspots`

```bash
python sast_cli.py --mode analyze --metric hotspots --repo-key juice_shop
```

This reads the latest normalized outputs and writes derived analysis artifacts under `runs/analysis/`.

## Running scanners directly (bypassing `sast_cli.py`)

You can run each tool entrypoint directly. These scripts are the stable integration contract used by the pipeline:

- `tools/scan_semgrep.py`
- `tools/scan_snyk.py`
- `tools/scan_sonar.py`
- `tools/scan_aikido.py`

### Semgrep

```bash
python tools/scan_semgrep.py   --repo-url https://github.com/juice-shop/juice-shop.git   --config p/security-audit   --output-root runs/semgrep
```

### Snyk

```bash
python tools/scan_snyk.py   --repo-url https://github.com/juice-shop/juice-shop.git   --output-root runs/snyk
```

### SonarCloud

Run scan + fetch issues:

```bash
python tools/scan_sonar.py   --repo-url https://github.com/juice-shop/juice-shop.git   --project-key <your_sonar_project_key>   --output-root runs/sonar
```

Fetch issues from an existing SonarCloud project without running a new scan:

```bash
python tools/scan_sonar.py   --repo-url https://github.com/juice-shop/juice-shop.git   --project-key <your_sonar_project_key>   --skip-scan   --output-root runs/sonar
```

### Aikido

```bash
python tools/scan_aikido.py   --git-ref <owner>/<repo>   --output-root runs/aikido
```

## Outputs

### Output layout

Runs are stored locally and are safe to delete/recompute.

```text
runs/
  semgrep/<repo_name>/<run_id>/
    <repo_name>.json
    <repo_name>.normalized.json
    metadata.json

  snyk/<repo_name>/<run_id>/
    <repo_name>.sarif
    <repo_name>.normalized.json
    metadata.json

  sonar/<repo_name>/<run_id>/
    <repo_name>.json
    <repo_name>.normalized.json
    <repo_name>_sonar_scan.log
    metadata.json

  aikido/<repo_name>/<run_id>/
    <repo_name>.json
    <repo_name>.normalized.json
    metadata.json

  analysis/<repo_name>/
    latest_hotspots_by_file.json
```

### Run IDs

Each run directory ID is `YYYYMMDDNN` (date + counter for that day).

## Option B packaging (keeping code clean)

We keep `tools/scan_*.py` as stable entrypoints and isolate tool logic behind per-scanner modules/packages to reduce “god scripts”.

See `ARCHITECTURE.md` for the full diagram and conventions.

## Repo hygiene

- `repos/` and `runs/` are generated. Do not commit them.
- Do not commit IDE folders like `.idea/`
- Never commit `.env` (tokens/secrets). If you add an `.env.example`, commit that instead.
