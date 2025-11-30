# SAST Benchmark Pipeline

This repo contains small, scriptable pipelines to run static analyzers (SAST tools) on real GitHub repos and save their raw JSON results plus benchmark metadata.

The idea: given a GitHub repo, each tool script produces:

- `<output-root>/YYYYMMDDXX/<repo_name>.json` – raw scanner output
- `<output-root>/YYYYMMDDXX/metadata.json` – scanner/version/run metadata

Later, separate analysis code can load these JSON files and compute things like noise level, security_ratio, precision/recall/F1, etc.

---

## Tools

### Semgrep

`tools/scan_semgrep.py`

- Clones a target Git repo locally under `repos/`.
- Runs Semgrep with a given ruleset (default: `p/security-audit`).
- Writes raw Semgrep JSON and a `metadata.json` file under a dated run folder.

### Aikido

`tools/scan_aikido.py`

- Uses the Aikido Public REST API.
- Lists the connected GitHub repos in your Aikido workspace.
- Chooses a repo **either**:
  - from `--git-ref` (repo name, `owner/repo`, or URL fragment), **or**
  - via a small interactive CLI menu if `--git-ref` is omitted and you run it in a real terminal.
- Optionally triggers a new scan for that repo (if your Aikido API client has the right scopes).
- Exports all Aikido issues, filters them to that repo’s `code_repo_id`, and writes JSON + metadata under a dated run folder.

---

## Requirements

Python 3.9+ and:

```bash
pip install semgrep requests
