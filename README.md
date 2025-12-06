# SAST Benchmark Pipeline

This repo is a small pipeline that runs multiple SAST tools on the **same codebase** (e.g. OWASP Juice Shop) and writes comparable JSON outputs per tool.

Each tool has a simple entrypoint script in `tools/`:

- `scan_semgrep.py`
- `scan_sonar.py`
- `scan_snyk.py`
- `scan_aikido.py`

Every script:

- Clones a Git repo into `repos/<repo_name>/`
- Runs the corresponding scanner
- Writes JSON + `metadata.json` under `runs/<tool>/<YYYYMMDDNN>/`

There is also a unified CLI, `sast_cli.py`, which can:

- Run a **single scan** with any tool
- Run a **runtime benchmark** across multiple tools

###repo is designed to run through 'python sast_cli.py' while in the 'sast-benchmark-pipeline'
---

## 1. Requirements

### General

- Python **3.9+** (tested with Python 3.10)
- `git` installed
- Python deps (from the repo root):

```bash
pip install -r requirements.txt
# or, if you don’t have that file yet:
pip install semgrep requests python-dotenv
```

### Environment variables (`.env`)

Create a `.env` file in the project root:

```dotenv
# Aikido
AIKIDO_CLIENT_ID=your_aikido_client_id
AIKIDO_CLIENT_SECRET=your_aikido_client_secret

# SonarCloud
SONAR_ORG=your_sonarcloud_org_key
SONAR_TOKEN=your_sonarcloud_token
SONAR_HOST=https://sonarcloud.io

# Snyk
SNYK_TOKEN=your_snyk_api_token
```

### Tool‑specific prerequisites

- **Semgrep**
  - `pip install semgrep`
- **Aikido**
  - Aikido workspace
  - Aikido Public REST API client (client ID + secret)
- **SonarCloud**
  - Java 17+
  - `git` installed
  - `sonar-scanner` CLI installed and on `PATH`
  - SonarCloud org + projects already created (or created once via the UI)
- **Snyk**
  - `snyk` CLI installed (`npm install -g snyk`)
  - A Snyk account + API token

---

## 2. Unified CLI (`sast_cli.py`)

The CLI has two modes:

- **scan** – run a single scanner against a target repo
- **benchmark** – run a benchmark suite (currently: runtime benchmark across tools)

### 2.1 Interactive usage

```bash
python sast_cli.py
```

You’ll see menus like:

- Choose an action:
  - Scan a repo with a single tool
  - Run benchmarks
- Then choose a scanner / target / benchmark suite from numbered menus.  
  - Only valid numbers are accepted.
  - Press `Z` at any menu to exit.

### 2.2 Non‑interactive examples

**Run a single scan (Snyk on Juice Shop)**

```bash
python sast_cli.py --mode scan --scanner snyk --target juice_shop
```

**Run a runtime benchmark (all tools) on Juice Shop**

```bash
python sast_cli.py --mode benchmark --target juice_shop
```

**Runtime benchmark for a subset of tools**

```bash
python sast_cli.py --mode benchmark   --target juice_shop   --scanners semgrep,snyk
```

Benchmark summary JSON will be written under `runs/benchmarks/`.

---

## 3. Individual Tools

You can still call each tool’s script directly if you want.

### 3.1 Semgrep

**Script:** `tools/scan_semgrep.py`

What it does:

- Clones a target Git repo locally under `repos/<repo_name>/`.
- Runs Semgrep using the specified configuration (default: `p/security-audit`).
- Writes raw Semgrep JSON results + `metadata.json` + normalized JSON under `runs/semgrep/...`.

**Usage (generic)**

```bash
python tools/scan_semgrep.py   --repo-url <GIT_REPO_URL>   --config p/security-audit   --output-root runs/semgrep
```

**Usage (Juice Shop)**

```bash
python tools/scan_semgrep.py   --repo-url https://github.com/juice-shop/juice-shop.git   --config p/security-audit   --output-root runs/semgrep
```

---

### 3.2 Aikido

**Script:** `tools/scan_aikido.py`

**Usage (generic)**

```bash
python tools/scan_aikido.py   --git-ref <owner/repo or repo_name>   --output-root runs/aikido
```

**Usage (Juice Shop)**

```bash
python tools/scan_aikido.py   --git-ref Chai80/juice-shop   --output-root runs/aikido
```

> Note: `--git-ref` should match how the repo appears in your Aikido workspace  
> (e.g. `OrgName/juice-shop` or just `juice-shop` depending on your setup).

---

### 3.3 SonarCloud (SonarScanner)

**Script:** `tools/scan_sonar.py`

**Usage (generic)**

```bash
python tools/scan_sonar.py   --repo-url <GIT_REPO_URL>   --output-root runs/sonar
```

**Usage (Juice Shop)**

```bash
python tools/scan_sonar.py   --repo-url https://github.com/juice-shop/juice-shop.git   --project-key chai80_juice_shop   --output-root runs/sonar
```

**Pull previous scan results without running a new scan**

```bash
python tools/scan_sonar.py   --repo-url https://github.com/juice-shop/juice-shop.git   --project-key chai80_juice_shop   --skip-scan   --output-root runs/sonar
```

---

### 3.4 Snyk Code

**Script:** `tools/scan_snyk.py`

What it does:

1. Clones the repo into `repos/<repo_name>/`
2. Runs:

   ```bash
   snyk code test --json-file-output <absolute_path>
   ```

3. Produces:
   - Raw SARIF-style Snyk output (`<repo>.json`)
   - Normalized output (`<repo>.normalized.json`)
   - Metadata about the scanner/version/commit/timing

**Usage (generic)**

```bash
python tools/scan_snyk.py   --repo-url <GIT_REPO_URL>   --output-root runs/snyk
```

**Usage (Juice Shop)**

```bash
python tools/scan_snyk.py   --repo-url https://github.com/juice-shop/juice-shop.git   --output-root runs/snyk
```

---

## 4. Unified Outputs

After running scans and benchmarks, you’ll see a structure like:

```bash
runs/
  semgrep/
    2025120201/
      juice-shop.json
      juice-shop.normalized.json
      metadata.json
  snyk/
    2025120201/
      juice-shop.json
      juice-shop.normalized.json
      metadata.json
  sonar/
    2025120201/
      juice-shop.json
      juice-shop.normalized.json
      juice-shop_sonar_scan.log
      metadata.json
  aikido/
    2025120201/
      juice-shop.json
      juice-shop.normalized.json
      metadata.json
  benchmarks/
    20251202T010406_juice_shop_runtime.json
```

Each run directory ID is `YYYYMMDDNN` (date + counter for that day).

---

## 5. Folder Layout Summary

```bash
sast-benchmark-pipeline/
├── benchmarks/
│   ├── __init__.py
│   ├── runtime.py              # benchmark suite runner
│   └── targets.py              # central BENCHMARKS + BENCHMARK_SUITES config
├── tools/
│   ├── run_utils.py            # shared helpers (clone repo, run dirs, git info)
│   ├── scan_semgrep.py
│   ├── scan_snyk.py
│   ├── scan_sonar.py
│   └── scan_aikido.py
├── repos/                      # cloned repos (auto-created)
├── runs/
│   ├── semgrep/<run_id>/
│   ├── snyk/<run_id>/
│   ├── sonar/<run_id>/
│   ├── aikido/<run_id>/
│   └── benchmarks/<timestamp>_<target>_runtime.json
├── sast_cli.py                 # unified CLI (scan + benchmark)
├── normalized-schema.md
├── README.md
├── requirements.txt
└── .env
```

---

## 6. Benchmark Targets

Our examples use 5 well‑known intentionally vulnerable applications:

| Logical name            | Upstream GitHub repo (`<GIT_REPO_URL>` for Semgrep/Sonar/Snyk) | Fork used in Aikido workspace (`--git-ref`) | SonarCloud project key (our setup) |
|-------------------------|-----------------------------------------------------------------|---------------------------------------------|------------------------------------|
| Juice Shop              | https://github.com/juice-shop/juice-shop.git                   | Chai80/juice-shop                           | chai80_juice_shop                  |
| DVPWA                   | https://github.com/vulnerable-apps/dvpwa.git                   | Chai80/dvpwa                                | chai80_dvpwa                       |
| OWASP Benchmark (Java)  | https://github.com/OWASP-Benchmark/BenchmarkJava.git           | Chai80/owasp_benchmark                      | chai80_owasp_benchmark             |
| Spring Boot RealWorld   | https://github.com/gothinkster/spring-boot-realworld-example-app.git | Chai80/spring_realworld             | chai80_spring_realworld            |
| vuln_node_express       | https://github.com/vulnerable-apps/vuln_node_express.git       | Chai80/vuln_node_express                    | chai80_vuln_node_express           |

- For **Semgrep**, **SonarCloud**, and **Snyk**, use the “Upstream GitHub repo” column as `<GIT_REPO_URL>`.
- For **Aikido**, use the “Fork used in Aikido workspace” column as `--git-ref`.
- The “SonarCloud project key” column shows how we named the projects in our own SonarCloud org; you can adapt these to your org.
