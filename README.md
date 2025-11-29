# SAST Benchmark Pipeline

This repo contains small, scriptable pipelines to run static analyzers on real GitHub repos and save JSON results plus benchmark metadata.

## Current tools

- `tools/scan_semgrep.py`: runs Semgrep on a target repo and stores JSON + metadata under a dated run folder.

## Requirements

```bash
pip install semgrep
```
# How to run the Semgrep pipeline
git clone https://github.com/Chai80/sast-benchmark-pipeline.git
cd sast-benchmark-pipeline

# Example: scan OWASP Juice Shop with the security-audit ruleset
python tools/scan_semgrep.py \
  --repo-url https://github.com/juice-shop/juice-shop.git \
  --config p/security-audit

This creates outputs:
runs/semgrep/YYYYMMDDXX/
  ├─ <repo_name>.json     # raw Semgrep JSON
  └─ metadata.json        # scanner version, repo URL, commit, command, timing

