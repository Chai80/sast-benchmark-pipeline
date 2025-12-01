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

---

## 1. Requirements (read this first)

### General

- Python **3.9+**
- `git` installed
- Python deps (from the repo root):

  ```bash
  pip install -r requirements.txt
  # or, if you don’t have that file yet:
  pip install semgrep requests python-dotenv

# Aikido
AIKIDO_CLIENT_ID=your_aikido_client_id
AIKIDO_CLIENT_SECRET=your_aikido_client_secret

# SonarCloud
SONAR_ORG=your_sonarcloud_org_key
SONAR_TOKEN=your_sonarcloud_token
SONAR_HOST=https://sonarcloud.io

# Snyk
SNYK_TOKEN=your_snyk_api_token

##Tool‑specific prerequisites
Semgrep CLI (via pip is easiest):

- For **Semgrep** and **SonarCloud**, use the *upstream* repo URLs above as `<GIT_REPO_URL>` (or swap in your own repos if you prefer).
- For **Aikido**, `--git-ref` should match the repo names as they appear in your Aikido workspace. In our case we connected forks under the `Chai80/...` GitHub account, so our examples use those values (e.g. `Chai80/juice-shop`). You should substitute your own forks if your workspace uses a different account.

---

## Requirements

- Python 3.9+
- `pip install semgrep requests`
- For **Aikido**: Aikido workspace + Public REST API client
- For **SonarCloud**:
  - Java 17+
  - `git` installed
  - `sonar-scanner` CLI installed and on `PATH`
  - SonarCloud org + project(s) already created

---

## Tools

### 1. Semgrep

**Script:** `tools/scan_semgrep.py`
What it does:

- Clones a target Git repo locally under `repos/<repo_name>/`.
- Runs Semgrep using the specified configuration (default: `p/security-audit`).
- Writes raw Semgrep JSON results + a `metadata.json` file under:


## Usage (generic)

```bash
python tools/scan_semgrep.py \
--repo-url <GIT_REPO_URL> \
--config p/security-audit \
--output-root runs/semgrep
```

## Usage (JuiceShop)

```bash
python tools/scan_semgrep.py \
  --repo-url https://github.com/juice-shop/juice-shop.git \
  --config p/security-audit \
  --output-root runs/semgrep
```

#Outputs
```bash
runs/semgrep/2025113001/juice-shop.json
runs/semgrep/2025113001/metadata.json
```

### 2. Aikido
**Script:** `tools/scan_aikido.py`

## Usage (generic)
```bash
python tools/scan_aikido.py \
  --git-ref <owner/repo or repo_name> \
  --output-root runs/aikido
```

## Usage (JuiceShop)
```bash
python tools/scan_aikido.py \
  --git-ref <owner/repo or repo_name> \
  --output-root runs/aikido
```

#Outputs
```bash
runs/aikido/2025113001/juice-shop.json
runs/aikido/2025113001/metadata.json
```
### 3. SonarCloud (SonarScanner)
**Script:** `tools/scan_sonar.py`

## Usage (generic)
```bash
python tools/scan_sonar.py \
  --repo-url <GIT_REPO_URL> \
  --output-root runs/sonar
```
## Usage (JuiceShop)
```bash
python tools/scan_sonar.py \
  --repo-url https://github.com/juice-shop/juice-shop.git \
  --project-key chai80_juice-shop \
  --output-root runs/sonar
```
##Pull previous scan results without running a current Scan
```bash
python tools/scan_sonar.py \
  --repo-url https://github.com/juice-shop/juice-shop.git \
  --project-key chai80_juice-shop \
  --skip-scan \
  --output-root runs/sonar
```

#Outputs
```bash
runs/sonar/2025113003/juice-shop.json
runs/sonar/2025113003/metadata.json
runs/sonar/2025113003/juice-shop_sonar_scan.log
```

### 4. SnykCode
**Script:** `tools/scan_snyk.py`

What it does:

1.Clones the repo into repos/<repo_name>/

2. Runs:

```bash
snyk code test --json-file-output <absolute_path>
```

Produces:

  -Raw SARIF-style Snyk output (<repo>.json)

  -Normalized output (<repo>.normalized.json)

  -Metadata about the scanner/version/commit/timing
  
## Usage (generic)

```bash
python tools/scan_snyk.py \
  --repo-url <GIT_REPO_URL> \
  --output-root runs/snyk
```

## Usage (JuiceShop)

```bash
python tools/scan_snyk.py \
  --repo-url https://github.com/juice-shop/juice-shop.git \
  --output-root runs/snyk
```

#Outputs
```bash
runs/snyk/2025113004/juice-shop.json
runs/snyk/2025113004/juice-shop.normalized.json
runs/snyk/2025113004/metadata.json
```

## Folder Layout Summary
```bash
sast-benchmark-pipeline/
├── tools/
│   ├── scan_semgrep.py
│   ├── scan_aikido.py
│   ├── scan_sonar.py
│   └── scan_snyk.py
├── repos/               # cloned repos (auto-created)
├── runs/
│   ├── semgrep/
│   ├── sonar/
│   ├── snyk/
│   └── aikido/
├── .env                 # DO NOT COMMIT
├── README.md
└── requirements.txt
```

## Possible BenchMarkRepos you can use to scan

Our examples use 5 well‑known intentionally vulnerable applications:

| Logical name            | Upstream GitHub repo (`<GIT_REPO_URL>` for Semgrep/Sonar/Snyk)                                                                 | Fork used in Aikido workspace (`--git-ref`) | SonarCloud project key (our setup) |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------|------------------------------------|
| Juice Shop              | https://github.com/juice-shop/juice-shop.git                                                                                   | Chai80/juice-shop                           | chai80_juice_shop                  |
| DVPWA                   | https://github.com/vulnerable-apps/dvpwa.git                                                                                   | Chai80/dvpwa                                | chai80_dvpwa                       |
| OWASP Benchmark (Java)  | https://github.com/OWASP-Benchmark/BenchmarkJava.git                                                                           | Chai80/owasp_benchmark                      | chai80_owasp_benchmark             |
| Spring Boot RealWorld   | https://github.com/gothinkster/spring-boot-realworld-example-app.git                                                           | Chai80/spring_realworld                     | chai80_spring_realworld            |
| vuln_node_express       | https://github.com/vulnerable-apps/vuln_node_express.git                                                                       | Chai80/vuln_node_express                    | chai80_vuln_node_express           |

- For **Semgrep**, **SonarCloud**, and **Snyk**, use the “Upstream GitHub repo” column as `<GIT_REPO_URL>`.
- For **Aikido**, use the “Fork used in Aikido workspace” column as `--git-ref`.
- The “SonarCloud project key” column shows how we named the projects in our own SonarCloud org; you can adapt these to your org.
