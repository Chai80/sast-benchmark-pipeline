# Architecture (Option B Packaging)

This repo uses **Option B**: keep stable script entrypoints (`tools/scan_*.py`) so the pipeline can shell out reliably, while moving tool-specific logic into per-scanner packages under `tools/<scanner>/`.

## Repository structure

```text
repo_root/
├─ sast_cli.py
├─ pipeline/
│  ├─ core.py
│  └─ analysis/
│     ├─ run_discovery.py
│     ├─ unique_overview.py
│     └─ path_normalization.py
│
├─ tools/
│  ├─ core.py
│  ├─ normalize_common.py
│  ├─ normalize_extractors.py
│  ├─ classification_resolver.py
│  │
│  ├─ scan_semgrep.py
│  ├─ scan_snyk.py
│  ├─ scan_sonar.py
│  └─ scan_aikido.py
│  │
│  ├─ semgrep/
│  │  ├─ __init__.py        # execute(...)
│  │  ├─ runner.py          # runs semgrep, writes raw artifacts
│  │  └─ normalize.py       # raw semgrep JSON -> normalized schema
│  │
│  ├─ snyk/
│  │  ├─ __init__.py        # execute(...)
│  │  ├─ runner.py          # runs snyk, writes SARIF/raw
│  │  ├─ sarif.py           # SARIF helpers (optional)
│  │  ├─ vendor_rules.py    # mapping helpers (optional)
│  │  └─ normalize.py       # SARIF -> normalized schema
│  │
│  ├─ sonar/
│  │  ├─ __init__.py
│  │  ├─ api.py
│  │  ├─ rules.py
│  │  ├─ types.py
│  │  └─ normalize.py
│  │
│  └─ aikido/
│     ├─ __init__.py        # execute(...)
│     ├─ runner.py          # orchestrates scan/export, writes raw
│     ├─ normalize.py       # raw Aikido issues -> normalized schema
│     └─ client.py          # optional HTTP client split
│
└─ mappings/
   ├─ cwe_to_owasp_top10_mitre.json
   └─ snyk_rule_to_owasp_2021.json
```

## Runtime flow

```text
User / CI
  |
  v
sast_cli.py
  |
  v
pipeline/core.py  (Orchestrator)
  |
  |  For each selected tool:
  |  - builds subprocess command:
  |      python tools/scan_<tool>.py <args...>
  v
tools/scan_<tool>.py  (Thin shim / stable entrypoint)
  |
  |  parses args
  |  calls tools.<tool>.execute(...)
  v
tools/<tool>/__init__.py
  |
  |-- runner.py      -> writes raw tool output
  |-- normalize.py   -> writes normalized schema output
  |
  v
runs/<tool>/<repo>/<run_id>/
  ├─ <raw outputs>
  ├─ <repo>.normalized.json
  └─ metadata.json / logs
  |
  v
pipeline/analysis/*
  - reads normalized outputs
  - produces derived reports under runs/analysis/
```

## Design rules

- The pipeline depends only on `tools/scan_*.py` paths (stable contract).
- Tool-specific logic lives inside `tools/<tool>/`.
- Normalized JSON is the cross-tool contract; analysis should not parse vendor raw formats.
- Shared helpers stay small and boring (`tools/core.py`, normalization helpers).
