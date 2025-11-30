# SAST Benchmark Pipeline

This repo contains small, scriptable pipelines to run static analyzers (SAST tools) on real GitHub repos and save their raw JSON results plus benchmark metadata.

Each tool script takes a GitHub repo and produces:

- `<output-root>/YYYYMMDDXX/<repo_name>.json` – raw scanner output (issues)
- `<output-root>/YYYYMMDDXX/metadata.json` – scanner/version/run metadata

You can then load these JSON files in separate analysis code to compute things like noise level, security_ratio, precision/recall/F1, etc.

---

## Benchmark repos used in this project

Our examples use 5 well-known intentionally vulnerable applications:

| Logical name           | Upstream GitHub repo (used for `<GIT_REPO_URL>` in Semgrep/Sonar)                 | Fork used in Aikido workspace (`--git-ref`) | SonarCloud project key (our setup)   |
|------------------------|-----------------------------------------------------------------------------------|---------------------------------------------|--------------------------------------|
| Juice Shop             | https://github.com/juice-shop/juice-shop.git                                     | Chai80/juice-shop                           | chai80_juice_shop                    |
| DVPWA                  | https://github.com/vulnerable-apps/dvpwa.git                                     | Chai80/dvpwa                                | chai80_dvpwa                         |
| OWASP Benchmark (Java) | https://github.com/OWASP-Benchmark/BenchmarkJava.git                              | Chai80/owasp_benchmark                      | chai80_owasp_benchmark               |
| Spring Boot RealWorld  | https://github.com/gothinkster/spring-boot-realworld-example-app.git             | Chai80/spring_realworld                     | chai80_spring_realworld              |
| vuln_node_express      | https://github.com/vulnerable-apps/vuln_node_express.git                         | Chai80/vuln_node_express                    | chai80_vuln_node_express             |

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

- Clones a target Git repo locally under `repos/`.
- Runs Semgrep with a given ruleset (default: `p/security-audit`).
- Writes raw Semgrep JSON and a `metadata.json` file under a dated run folder.

**Generic usage**

```bash
python tools/scan_semgrep.py \
  --repo-url <GIT_REPO_URL> \
  --config p/security-audit \
  --output-root runs/semgrep
```
**Example (Juice Shop)**

```bash
python tools/scan_semgrep.py \
  --repo-url https://github.com/juice-shop/juice-shop.git \
  --config p/security-audit \
  --output-root runs/semgrep
```
**Outputs (example)**
runs/semgrep/2025113001/juice-shop.json
runs/semgrep/2025113001/metadata.json

### 2. Aikido

**Script:** `tools/scan_aikido.py`

What it does:

- Uses the Aikido Public REST API.
- Lists the connected GitHub repos in your Aikido workspace.
- Chooses a repo **either**:
  - from `--git-ref` (repo name, `owner/repo`, or URL fragment), **or**
  - via a small interactive CLI menu if `--git-ref` is omitted and you run it in a real terminal.
- Triggers a scan when possible, then exports Aikido issues for that repo.
- Writes JSON + metadata under a dated run folder.

**Generic usage**

```bash
export AIKIDO_CLIENT_ID=<your_client_id>
export AIKIDO_CLIENT_SECRET=<your_client_secret>
python tools/scan_aikido.py \
  --git-ref <owner/repo or repo_name> \
  --output-root runs/aikido
```
** Example **

export AIKIDO_CLIENT_ID=your_client_id
export AIKIDO_CLIENT_SECRET=your_client_secret

python tools/scan_aikido.py \
  --git-ref Chai80/juice-shop \
  --output-root runs/aikido


```bash
export AIKIDO_CLIENT_ID=<your_client_id>
export AIKIDO_CLIENT_SECRET=<your_client_secret>
python tools/scan_aikido.py \
  --git-ref <owner/repo or repo_name> \
  --output-root runs/aikido
```

** Example scan_aikido.py run **

```bash
export AIKIDO_CLIENT_ID=your_client_id
export AIKIDO_CLIENT_SECRET=your_client_secret

python tools/scan_aikido.py \
  --git-ref Chai80/juice-shop \
  --output-root runs/aikido
```


**Outputs (example)**
runs/aikido/2025113001/juice-shop.json
runs/aikido/2025113001/metadata.json


### 3. SonarScan
**Script:** `tools/scan_sonar.py`

**Generic usage**

```bash
export SONAR_ORG=<your_sonarcloud_org_key>   # e.g. chai80
export SONAR_TOKEN=<your_sonarcloud_token>   # do NOT commit this
# optional, defaults to SonarCloud:
# export SONAR_HOST=https://sonarcloud.io
```

** Example scan_sonar.py run **

```bash
export SONAR_ORG=chai80
export SONAR_TOKEN=your_sonarcloud_token

python tools/scan_sonar.py \
  --repo-url https://github.com/Chai80/juice-shop.git \
  --project-key chai80_juice_shop \
  --output-root runs/sonar
```

If you only want to pull the current issues (and not trigger a new scan):
```bash
python tools/scan_sonar.py \
  --repo-url https://github.com/Chai80/juice-shop.git \
  --project-key chai80_juice_shop \
  --skip-scan \
  --output-root runs/sonar
```
**Outputs (example)**
runs/sonar/2025113003/juice-shop.json
runs/sonar/2025113003/metadata.json
