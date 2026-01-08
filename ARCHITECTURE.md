# Architecture 

- Keep **stable script entrypoints** (`tools/scan_*.py`) so the pipeline can shell out reliably.
- Move **tool-specific logic** into isolated packages under `tools/<tool>/`.
- Treat **normalized JSON** as the cross-tool contract consumed by all analysis code.
- Write results in a **suite/case layout** by default so data is easier to browse and ingest into a database later.
- For system-level diagrams (end-to-end flow + analysis internals), see `docs/SYSTEM_DIAGRAMS.md`.

The primary goal is to enforce clear ownership,
one-way dependencies, and a single source of truth for shared logic.

---

## Repository Structure (Layered)

```text
repo_root/
├─ sast_cli.py
├─ pipeline/
│  ├─ core.py
│  ├─ bundles.py                # suite/case output layout helpers
│  └─ analysis/
│     ├─ run_discovery.py       # finds “latest run per tool” (supports v1 + v2 layouts)
│     ├─ analyze_suite.py       # cross-tool suite metrics (location/taxonomy agreement)
│     ├─ gt_scorer.py           # GT scoring (writes gt/gt_score.* when used)
│     ├─ unique_overview.py
│     └─ path_normalization.py
│
├─ tools/
│  │
│  │  Stable entrypoints (subprocess contract)
│  ├─ scan_semgrep.py
│  ├─ scan_snyk.py
│  ├─ scan_sonar.py
│  └─ scan_aikido.py
│  │
│  │  Shared platform helpers (no tool-specific parsing here)
│  ├─ io.py                     # canonical JSON + file IO helpers
│  └─ core.py                   # orchestration helpers / legacy re-exports
│  │
│  │  Canonical shared normalization layer
│  ├─ normalize/
│  │  ├─ common.py              # schema builders (repo, scan metadata)
│  │  ├─ extractors.py          # shared extraction (location, tags, CWE, text)
│  │  └─ classification.py      # CWE / OWASP resolution and mapping logic
│  │
│  │  Compatibility shims (forwarding modules only)
│  │  - kept so older imports don’t break after refactors
│  ├─ normalize_common.py
│  ├─ normalize_extractors.py
│  └─ classification_resolver.py
│  │
│  │  Tool-specific packages (each tool isolated)
│  ├─ semgrep/
│  │  ├─ __init__.py            # execute(...)
│  │  ├─ runner.py              # runs semgrep; writes raw artifacts
│  │  └─ normalize.py           # raw -> normalized (uses tools/normalize/*)
│  │
│  ├─ snyk/
│  │  ├─ __init__.py
│  │  ├─ runner.py
│  │  ├─ sarif.py
│  │  ├─ vendor_rules.py
│  │  └─ normalize.py
│  │
│  ├─ sonar/
│  │  ├─ __init__.py
│  │  ├─ api.py
│  │  ├─ rules.py
│  │  ├─ types.py
│  │  └─ normalize.py
│  │
│  └─ aikido/
│     ├─ __init__.py
│     ├─ runner.py
│     ├─ normalize.py
│     └─ client.py
│
└─ mappings/
   ├─ cwe_to_owasp_top10_mitre.json
   └─ snyk_rule_to_owasp_2021.json
```

---

## Filesystem Layout (Outputs)

This repo supports **two output layouts**:

### v2 (suite/case layout, preferred)

This is the default when running via `sast_cli.py` (unless you pass `--no-suite`).

```text
runs/
  suites/<suite_id>/
    suite.json
    summary.csv
    cases/<case_id>/
      case.json
      tool_runs/<tool>/<run_id>/
        run.json
        normalized.json
        raw.(json|sarif)
        metadata.json
        logs/...
      analysis/...
      gt/gt_score.(json|csv)    # if GT scorer is used
```

**Why v2 exists:** it’s easier to browse, and it’s much easier to ingest into a DB because
`suite.json`, `case.json`, and `run.json` provide stable pointers and IDs.

### v1 (legacy)

Used when running scanners directly with `--output-root runs/<tool>` or when you pass `--no-suite`.

```text
runs/<tool>/<repo_name>/<run_id>/
  <repo_name>.normalized.json
  <repo_name>.json | <repo_name>.sarif
  metadata.json
```

---

## Process Flow (End-to-End)

```text
                 +--------------------------+
                 |        sast_cli.py       |
                 |  (choose repo/tool/suite)|
                 +------------+-------------+
                              |
                              v
                 +--------------------------+
                 |     pipeline/core.py     |
                 |  (orchestrates scans)    |
                 +------------+-------------+
                              |
                              | stable subprocess contract:
                              | python tools/scan_<tool>.py <args...>
                              v
        +---------------------+-----------------------+---------------------+
        |                     |                       |                     |
        v                     v                       v                     v
+-------------------+  +-------------------+   +-------------------+  +-------------------+
| tools/scan_snyk.py |  | tools/scan_semgrep|   | tools/scan_sonar.py|  | tools/scan_aikido |
| (thin shim)        |  | .py (thin shim)   |   | (thin shim)        |  | .py (thin shim)  |
+---------+---------+  +---------+---------+   +---------+---------+  +---------+---------+
          |                      |                       |                     |
          | calls                | calls                 | calls               | calls
          v                      v                       v                     v
+-------------------+  +-------------------+   +-------------------+  +-------------------+
| tools/snyk/        |  | tools/semgrep/    |   | tools/sonar/       |  | tools/aikido/     |
| execute(...)       |  | execute(...)      |   | execute(...)       |  | execute(...)      |
+---------+---------+  +---------+---------+   +---------+---------+  +---------+---------+
          |                      |                       |                     |
          | runner -> raw output | runner -> raw output  | runner/api -> raw   | runner -> raw output
          | normalize ->         | normalize ->          | normalize ->        | normalize ->
          | normalized JSON      | normalized JSON       | normalized JSON     | normalized JSON
          v                      v                       v                     v

                 +--------------------------------------------------+
                 |              SHARED NORMALIZATION                 |
                 | tools/normalize/common.py  (schema builders)      |
                 | tools/normalize/extractors.py (location/tags/CWE) |
                 | tools/normalize/classification.py (CWE->OWASP)    |
                 | tools/io.py (read/write JSON, read_line_content)  |
                 +---------------------------+---------------------- +
                                             |
                                             v
                 +--------------------------------------------------+
                 |                   OUTPUTS                         |
                 | v2: runs/suites/<suite_id>/cases/<case_id>/        |
                 |       tool_runs/<tool>/<run_id>/normalized.json    |
                 |       + raw + metadata + run.json                  |
                 |     + case.json + suite.json for DB ingestion      |
                 | v1: runs/<tool>/<repo>/<run_id>/<repo>.normalized  |
                 +---------------------------+---------------------- +
                                             |
                                             v
                 +--------------------------------------------------+
                 |              pipeline/analysis/*                   |
                 | - discovers latest normalized runs                 |
                 | - computes convergence metrics                     |
                 | - writes derived reports (analysis/)               |
                 | - optionally runs GT scoring (gt/)                 |
                 +--------------------------------------------------+
```

---

## Compatibility Shims (Plain English)

The modules:
- `tools/normalize_common.py`
- `tools/normalize_extractors.py`
- `tools/classification_resolver.py`

exist only to keep **old import paths working** after shared normalization code was
moved into the canonical package `tools/normalize/`.

They must contain **no real logic** and only re-export symbols from the canonical modules.

**Rule:** new code should import from `tools/normalize/*` directly.

---

## Mappings (Ground Truth Reference Data)

The `mappings/` directory contains **data-only reference tables**, such as:

- CWE → OWASP Top 10 mappings
- Vendor rule ID → OWASP mappings (e.g., Snyk)

These files are treated as **ground truth inside this system**, but they are interpreted
in exactly one place:

- `tools/normalize/classification.py`

**Rule:** tool normalizers must NOT load mapping files directly.

---

## Design Rules (Anti-Spaghetti Constraints)

1. **Stable contract**
   - The pipeline depends only on `tools/scan_*.py` paths.

2. **Tool isolation**
   - Tool packages (`tools/<tool>/`) must not import other tools.

3. **Single source of truth**
   - File/JSON IO lives in `tools/io.py`.
   - Shared normalization logic lives in `tools/normalize/*`.

4. **Dependency direction**
   - `tools/<tool>/*` → may import `tools.normalize.*`, `tools.io`
   - `tools/normalize/*` → must NOT import `tools/<tool>/*`

5. **Normalized JSON is the contract**
   - Analysis code must not parse vendor raw formats.
