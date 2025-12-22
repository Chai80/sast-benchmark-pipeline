# SAST Benchmark Pipeline

This repo is a small pipeline that runs multiple SAST tools on the **same codebase** (e.g. OWASP Juice Shop) and writes **comparable JSON outputs** per tool:

- Raw tool output (`<repo>.json`)
- Normalized output (`<repo>.normalized.json`) using `normalized-schema.md` (schema v1.1)
- `metadata.json` (tool version, commit SHA, command, timings, etc.)

Supported tools (see `tools/`):

- `scan_semgrep.py`
- `scan_sonar.py`
- `scan_snyk.py`
- `scan_aikido.py`

There is also a unified CLI entrypoint:

- `sast_cli.py` — interactive menus or fully non-interactive flags


---

## Quickstart (recommended)

From the repo root:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python sast_cli.py --mode scan --scanner semgrep --target juice_shop
```

Outputs will appear under `runs/` (see “Outputs” below).


---

## Requirements

### General

- Python **3.10+**
  - The codebase uses Python 3.10 syntax (e.g. `Path | str`).
- `git` installed
- Python dependencies:

```bash
pip install -r requirements.txt
```

> Notes:
> - `semgrep` can be installed via pip (recommended) or separately as a CLI.
> - `sonar-scanner` and `snyk` are external CLIs and are not installed via `requirements.txt`.

### Environment variables (`.env`)

Create a `.env` file in the project root (or copy from `.env.example`):

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

### Tool-specific prerequisites

#### Semgrep
- Install Semgrep:
  ```bash
  pip install semgrep
  ```

#### Snyk Code
- Install Snyk CLI:
  ```bash
  npm install -g snyk
  ```
- Set `SNYK_TOKEN` in `.env`

#### SonarCloud (sonar-scanner)
- Java **17+**
- `sonar-scanner` installed and available on `PATH`
- SonarCloud org + projects set up (or created once via UI)
- Set `SONAR_ORG`, `SONAR_TOKEN`, and optionally `SONAR_HOST`

#### Aikido
- Aikido workspace + Public REST API credentials
- Set `AIKIDO_CLIENT_ID` and `AIKIDO_CLIENT_SECRET`


---

## Unified CLI (`sast_cli.py`)

### Interactive usage

```bash
python sast_cli.py
```

- Menus let you pick scan vs benchmark, tool, target, etc.
- Press `Z` to exit at any menu.

### Non-interactive examples

**Single scan (Snyk on Juice Shop)**

```bash
python sast_cli.py --mode scan --scanner snyk --target juice_shop
```

**Single scan, show the command only (no execution)**

```bash
python sast_cli.py --mode scan --scanner semgrep --target juice_shop --dry-run
```

**Runtime benchmark (all tools) on Juice Shop**

```bash
python sast_cli.py --mode benchmark --suite runtime --target juice_shop
```

**Runtime benchmark for a subset of tools**

```bash
python sast_cli.py --mode benchmark --suite runtime --target juice_shop --scanners semgrep,snyk
```

Benchmark summary JSON will be written under `runs/benchmarks/` unless `--no-save-benchmark` is used.


---

## Running tools directly (optional)

You can run each tool script directly instead of using `sast_cli.py`.

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

```bash
python tools/scan_sonar.py \
  --repo-url https://github.com/juice-shop/juice-shop.git \
  --project-key chai80_juice_shop \
  --output-root runs/sonar
```

Pull issues from an existing SonarCloud project without running a new scan:

```bash
python tools/scan_sonar.py \
  --repo-url https://github.com/juice-shop/juice-shop.git \
  --project-key chai80_juice_shop \
  --skip-scan \
  --output-root runs/sonar
```

### Aikido

```bash
python tools/scan_aikido.py \
  --git-ref Chai80/juice-shop \
  --output-root runs/aikido
```


---

## Outputs

### Preferred output layout (Semgrep / Snyk / Sonar)

These tools group outputs by repo name:

```bash
runs/
  semgrep/
    juice-shop/
      2025120201/
        juice-shop.json
        juice-shop.normalized.json
        metadata.json
  snyk/
    juice-shop/
      2025120201/
        juice-shop.json
        juice-shop.normalized.json
        metadata.json
  sonar/
    juice-shop/
      2025120201/
        juice-shop.json
        juice-shop.normalized.json
        juice-shop_sonar_scan.log
        metadata.json
```

### Aikido output layout (current)

Aikido currently writes into:

```bash
runs/
  aikido/
    2025120201/
      juice-shop.json
      juice-shop.normalized.json
      metadata.json
```

> If you want perfect consistency, update `tools/scan_aikido.py` to also write under `runs/aikido/<repo_name>/<run_id>/` like the others.

### Run IDs
Each run directory ID is `YYYYMMDDNN` (date + counter for that day).


---

## Benchmark Targets

Targets are defined in `benchmarks/targets.py`.

| Target key             | Repo URL (Semgrep/Snyk/Sonar) | Aikido ref | SonarCloud project key (example) |
|------------------------|--------------------------------|------------|----------------------------------|
| `juice_shop`           | https://github.com/juice-shop/juice-shop.git | Chai80/juice-shop | chai80_juice_shop |
| `dvpwa`                | https://github.com/vulnerable-apps/dvpwa.git | Chai80/dvpwa | chai80_dvpwa |
| `owasp_benchmark`      | https://github.com/OWASP-Benchmark/BenchmarkJava.git | Chai80/owasp_benchmark | chai80_owasp_benchmark |
| `spring_realworld`     | https://github.com/gothinkster/spring-boot-realworld-example-app.git | Chai80/spring_realworld | chai80_spring_realworld |
| `vuln_node_express`    | https://github.com/vulnerable-apps/vuln_node_express.git | Chai80/vuln_node_express | chai80_vuln_node_express |


---

## Folder Layout Summary

```bash
sast-benchmark-pipeline/
├── benchmarks/
│   ├── __init__.py
│   ├── runtime.py              # benchmark suite runner
│   └── targets.py              # central TARGETS config used by CLI
├── tools/
│   ├── run_utils.py            # shared helpers (clone repo, run dirs, git info)
│   ├── scan_semgrep.py
│   ├── scan_snyk.py
│   ├── scan_sonar.py
│   └── scan_aikido.py
├── repos/                      # cloned repos (auto-created; do not commit)
├── runs/                       # outputs (auto-created; do not commit)
├── sast_cli.py                 # unified CLI (scan + benchmark)
├── normalized-schema.md
├── README.md
├── requirements.txt
└── .env                        # do not commit; use .env.example
```


---

## Repo hygiene notes

- `repos/` and `runs/` are generated. Do not commit them.
- Do not commit IDE folders like `.idea/`
- Commit `.env.example` (but never commit `.env`)
