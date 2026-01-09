# SAST Benchmark & Normalization Pipeline

This repo runs multiple security scanners (Semgrep, SonarCloud/SonarScanner, Snyk Code, Aikido) against a target repository and writes **comparable outputs** per tool:

- **Bronze (raw):** raw tool output (`raw.json` / `raw.sarif`), logs (when available), and `metadata.json`
- **Silver (normalized):** `normalized.json` using the contract in `normalized-schema.md`
- **Gold (analysis):** derived case/suite metrics under `analysis/` (agreement, hotspots, GT scoring outputs, etc.)
- **Optional (warehouse export):** `export/` JSONL tables designed for ingestion into systems like BigQuery

## Documentation

- **Architecture:** `ARCHITECTURE.md`
- **Normalized output contract:** `normalized-schema.md`

## Concepts (how to think about runs)

This pipeline supports two output styles:

### Suite layout (preferred, DB/ETL-friendly)

A **suite** is one experiment run (one `suite_id`), and a **case** is one scan target inside the suite (e.g., a repo URL, a local checkout, or a branch/worktree checkout).

Within a case, each scanner produces a **tool run** (one tool × one case × one `run_id`).

### Legacy layout (still supported)

You can disable suite layout and write directly to `runs/<tool>/...` for quick one-off scans.

## Inputs (what gets scanned)

### `repos/` is an input cache

When you scan a repo URL, the pipeline will clone into `repos/<repo_name>/` by default.

This is **not output data**. Treat it as a cache:
- safe to delete at any time
- do not commit it
- you can keep it around to speed up repeated runs

### `repos/worktrees/` is for “branch-per-case” suites

If your benchmark suite is **one branch = one test case**, you typically want a separate checkout per branch.

We support that by using `git worktree` checkouts under:

```text
repos/worktrees/<repo_name>/<branch_name>/
```

The CLI **does not** automatically generate worktrees for you — you prepare these inputs once, then run suite mode against them.

We provide a helper script:

```bash
bash scripts/make_worktrees.sh https://github.com/Chai80/durinn-owasp2021-python-micro-suite.git
```

This creates worktrees and writes a CSV you can feed into suite mode:
`suites/durinn-owasp2021-python-micro-suite_cases.csv`.

## Requirements

### General

- Python **3.10+**
- `git` available on your `PATH`

### Scanner prerequisites

- **Semgrep**: installed via `pip install semgrep` or available on PATH
- **Snyk**: install Snyk CLI and set `SNYK_TOKEN`
- **Sonar**: install `sonar-scanner` and set `SONAR_TOKEN` + `SONAR_ORG`
- **Aikido**: set `AIKIDO_CLIENT_ID` + `AIKIDO_CLIENT_SECRET` (and whatever Aikido requires)

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

### 2) Run multiple scanners on one target (benchmark mode)

```bash
python sast_cli.py --mode benchmark --repo-key juice_shop --scanners semgrep,snyk,sonar,aikido
```

If you want to control the suite id (useful in CI):

```bash
python sast_cli.py --mode benchmark --repo-key juice_shop --scanners semgrep,snyk,sonar --suite-id 20260107T120000Z
```

### 3) Run a multi-case suite (suite mode)

Use **suite mode** when you want to run the same scanner set across **many cases**
(e.g., multiple repos, or multiple branch/worktree checkouts) and keep everything
grouped under one `suite_id`.

There are 4 ways to define suite cases:

1) **Interactive** (no flags): prompts you case-by-case
2) **CSV** via `--cases-from` (recommended for branch-per-case suites)
3) **Worktree discovery** via `--worktrees-root` (auto-discovers checkouts)
4) **Python suite file** via `--suite-file` (power-user / advanced overrides)

#### 3a) Suite from a cases CSV (recommended)

Prepare worktrees + generate CSV:

```bash
bash scripts/make_worktrees.sh https://github.com/Chai80/durinn-owasp2021-python-micro-suite.git
```

Then run a smoke suite (first 3 cases):

```bash
python sast_cli.py --mode suite   --suite-id durinn_smoke   --scanners semgrep,snyk,sonar   --cases-from suites/durinn-owasp2021-python-micro-suite_cases.csv   --max-cases 3
```

Tip: there is also an end-to-end helper:

```bash
bash scripts/smoke_micro_suite.sh durinn-owasp2021-python-micro-suite
```

#### 3b) Suite by discovering worktrees under a folder

If you already have checkouts under a folder, you can skip the CSV and let the CLI discover them:

```bash
python sast_cli.py --mode suite   --suite-id durinn_all_branches   --scanners semgrep,snyk,sonar   --worktrees-root repos/worktrees/durinn-owasp2021-python-micro-suite
```

#### 3c) Suite from a Python suite definition file

`--suite-file` expects a Python file that exports `SUITE_DEF`.

Example (minimal):

```python
# suites/example_suite.py
from sast_cli import SuiteDef, SuiteCase, SuiteCaseOverrides, CaseSpec, RepoSpec, SuiteAnalysisConfig

SUITE_DEF = SuiteDef(
    suite_id="example_suite",
    scanners=["semgrep", "snyk", "sonar"],
    analysis=SuiteAnalysisConfig(skip=False, tolerance=3, filter="security"),
    cases=[
        SuiteCase(
            case=CaseSpec(
                case_id="juice-shop",
                runs_repo_name="juice-shop",
                label="Juice Shop",
                repo=RepoSpec(repo_key="juice_shop"),
            ),
            overrides=SuiteCaseOverrides(),
        ),
    ],
)
```

Run it:

```bash
python sast_cli.py --mode suite --suite-file suites/example_suite.py
```

### 4) Export a suite to JSONL tables for BigQuery ingestion (export mode)

Export mode turns an existing suite folder into a small set of **append-only JSONL datasets**
with stable schemas (see `schemas/bq/v1/`).

```bash
python sast_cli.py --mode export --suite-id durinn_smoke --export-schema-version v1
```

Or export the most recent suite:

```bash
python sast_cli.py --mode export --suite-id latest
```

Exports are written to:

```text
runs/suites/<suite_id>/export/v1/
  suites.jsonl
  cases.jsonl
  tool_runs.jsonl
  findings.jsonl
  export_manifest.json
```

### 5) Analyze an existing suite/case (analyze mode)

Analyze the latest suite case (suite metric):

```bash
python sast_cli.py --mode analyze --metric suite --repo-key juice_shop --suite-id latest
```

### 6) Legacy behavior (write directly to runs/<tool>/...)

```bash
python sast_cli.py --mode benchmark --repo-key juice_shop --scanners semgrep,snyk,sonar --no-suite
```

## Running scanners directly (bypassing `sast_cli.py`)

You can run each tool entrypoint directly. These scripts are the stable integration contract used by the pipeline:

- `tools/scan_semgrep.py`
- `tools/scan_snyk.py`
- `tools/scan_sonar.py`
- `tools/scan_aikido.py`

**Tip:** prefer running scanners as modules (avoids `PYTHONPATH` surprises):

```bash
python -m tools.scan_semgrep --help
python -m tools.scan_sonar --help
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
          analysis/                # derived metrics for this case
          gt/                      # GT-based scoring outputs (if run)
      export/v1/                   # JSONL tables for warehouse ingestion (optional)
        suites.jsonl
        cases.jsonl
        tool_runs.jsonl
        findings.jsonl
        export_manifest.json
```

### Legacy layout (v1, still supported)

If you pass `--no-suite`, or you call `tools/scan_*.py` directly with `--output-root runs/<tool>`, outputs use the legacy layout:

```text
runs/<tool>/<repo_name>/<run_id>/
  <repo_name>.normalized.json
  <repo_name>.json | <repo_name>.sarif
  metadata.json
```

## IDs and naming conventions

### Suite IDs (`suite_id`)

`suite_id` is the primary “batch key” for everything under `runs/suites/<suite_id>/`.

- You **can** name it yourself (e.g. `durinn_smoke2`, `micro-smoke-20260109T012345Z`)
- It will be sanitized to a safe folder segment (spaces → `_`, etc.)
- Treat it as **immutable** once you run a suite (changing it changes all paths/keys)

Recommended patterns:
- `YYYYMMDDTHHMMSSZ` (UTC timestamp)
- `<label>-YYYYMMDDTHHMMSSZ` (human label + timestamp)

### Tool run IDs (`run_id`)

Tool run directory ids are sortable timestamps. Current format is typically:

- `YYYYMMDDNNHHMMSS` (16 digits)

Older runs may use a shorter legacy form.

## DB ingestion / ETL notes

### Normalized JSON is “cleaned”, but still nested

`normalized.json` is the **cross-tool contract** and is great for:
- cross-tool comparisons (agreement, hotspot overlap)
- debugging tool behaviors
- reproducibility and provenance

But it is still nested JSON. For warehousing (BigQuery, etc.) you usually want a small number of stable, typed tables.

### Use export mode for stable BigQuery ingestion

Export mode writes JSONL tables with stable schemas:
- `schemas/bq/v1/suites.schema.json`
- `schemas/bq/v1/cases.schema.json`
- `schemas/bq/v1/tool_runs.schema.json`
- `schemas/bq/v1/findings.schema.json`

A simple ingestion flow is:
1) run scan/suite → produces `runs/suites/<suite_id>/...`
2) run export → produces `runs/suites/<suite_id>/export/v1/*.jsonl`
3) load those JSONL files into BigQuery (one table per file)

## Repo hygiene

- `repos/` and `runs/` are generated. Do not commit them.
- Do not commit IDE folders like `.idea/`
- Never commit `.env` (tokens/secrets). If you add an `.env.example`, commit that instead.

## Troubleshooting

- If you see `zsh: command not found: #`, you pasted a shell comment line into your terminal. Remove the comment lines or run `setopt interactivecomments`.
- If `python -m compileall .` fails, it may be compiling vendored code under `repos/`. Prefer:
  `python -m compileall -q pipeline tools sast_benchmark api scripts tests`.

## Developer notes

Before making large changes to the CLI UX, keep a snapshot of the current interface and verify that basic codepaths still work.

- `docs/cli_help_before_refactor.txt` is the baseline output of `python sast_cli.py --help`.
- `scripts/smoke_cli_dry_run.sh` exercises dry-run scan/benchmark codepaths without requiring any API tokens.
