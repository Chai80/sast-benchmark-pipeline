## Benchmark repos used in this project

Our examples use 5 well-known intentionally vulnerable applications:

| Logical name            | Upstream GitHub repo (used for `<GIT_REPO_URL>` in Semgrep/Sonar)                  | Fork used in Aikido workspace (`--git-ref`) | SonarCloud project key (our setup)   |
|-------------------------|-------------------------------------------------------------------------------------|---------------------------------------------|--------------------------------------|
| Juice Shop              | https://github.com/juice-shop/juice-shop.git                                      | Chai80/juice-shop                           | chai80_juice_shop                    |
| DVPWA                   | https://github.com/vulnerable-apps/dvpwa.git                                      | Chai80/dvpwa                                | chai80_dvpwa                         |
| OWASP Benchmark (Java)  | https://github.com/OWASP-Benchmark/BenchmarkJava.git                               | Chai80/owasp_benchmark (fork of Benchmark)  | chai80_owasp_benchmark               |
| Spring Boot RealWorld   | https://github.com/gothinkster/spring-boot-realworld-example-app.git              | Chai80/spring_realworld                     | chai80_spring_realworld              |
| vuln_node_express       | https://github.com/vulnerable-apps/vuln_node_express.git                          | Chai80/vuln_node_express                    | chai80_vuln_node_express             |

- For **Semgrep** and **SonarCloud**, use the *upstream* repo URLs above as `<GIT_REPO_URL>` (or swap in your own repos if you prefer).
- For **Aikido**, `--git-ref` should match the repo names as they appear in your Aikido workspace. In our case we connected forks under the `Chai80/…` GitHub account, so our examples use those values (e.g. `Chai80/juice-shop`). You should substitute your own forks if your workspace uses a different account.

#Steps to Run
git clone https://github.com/Chai80/sast-benchmark-pipeline.git
cd sast-benchmark-pipeline

# Python deps
pip install semgrep requests

Then for each tool:

###Semgrep

python tools/scan_semgrep.py \
  --repo-url <GIT_REPO_URL> \
  --config p/security-audit \
  --output-root runs/semgrep

***Example scan_semgrep.py run
python tools/scan_semgrep.py \
  --repo-url https://github.com/juice-shop/juice-shop.git \
  --config p/security-audit \
  --output-root runs/semgrep


###Aikido

export AIKIDO_CLIENT_ID=<your_client_id>
export AIKIDO_CLIENT_SECRET=<your_client_secret>

python tools/scan_aikido.py \
  --git-ref <owner/repo or repo_name> \
  --output-root runs/aikido

***Example scan_aikido.py run
export AIKIDO_CLIENT_ID=your_client_id
export AIKIDO_CLIENT_SECRET=your_client_secret

python tools/scan_aikido.py \
  --git-ref Chai80/juice-shop \
  --output-root runs/aikido


###SonarCloud

export SONAR_ORG=<your_sonarcloud_org_key>   # e.g. chai80
export SONAR_TOKEN=<your_sonarcloud_token>   # do NOT commit this
# sonar-scanner CLI must be installed and on PATH

python tools/scan_sonar.py \
  --repo-url <GIT_REPO_URL> \
  --project-key <sonar_project_key> \
  --output-root runs/sonar
  
***Example scan_sonar.py run
export SONAR_ORG=your_sonarcloud_org_key   # e.g. chai80
export SONAR_TOKEN=your_sonarcloud_token   # do NOT commit this
# sonar-scanner CLI must be installed and on PATH

python tools/scan_sonar.py \
  --repo-url https://github.com/Chai80/juice-shop.git \
  --project-key chai80_juice_shop \
  --output-root runs/sonar


Each run will create a dated folder:
runs/semgrep/YYYYMMDDXX/

runs/aikido/YYYYMMDDXX/

runs/sonar/YYYYMMDDXX/

containing <repo_name>.json and metadata.json for that scanner.
