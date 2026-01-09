# Architecture

- Keep **stable script entrypoints** (`tools/scan_*.py`) so the pipeline can shell out reliably.
- Move **tool-specific logic** into isolated packages under `tools/<tool>/`.
- Treat **normalized JSON** as the cross-tool contract consumed by all analysis code.
- Centralize **domain types** (e.g., the normalized Finding) and **run layout logic** so the filesystem/data contract is owned by one place.
- Write results in a **suite/case layout** by default so data is easier to browse and ingest into a database later.
- Provide an optional **warehouse export** step that emits stable JSONL tables for ingestion (e.g., BigQuery).
- For system-level diagrams (end-to-end flow + analysis internals), see `docs/SYSTEM_DIAGRAMS.md`.

The primary goal is to enforce clear ownership,
one-way dependencies, and a single source of truth for shared logic.

---

## Repository Structure

```text
repo_root/
├─ sast_cli.py
├─ sast_benchmark/
│  ├─ domain/
│  │  └─ finding.py              # normalized Finding dataclass/schema
│  └─ io/
│     └─ layout.py               # canonical run path/layout helpers (RunPaths)
│
├─ pipeline/
│  ├─ core.py
│  ├─ bundles.py                 # suite/case bundle layout + IDs + safe_name
│  ├─ export/
│  │  ├─ __init__.py
│  │  └─ bq_export.py            # suite -> JSONL table exports for BigQuery (optional)
│  └─ analysis/
│     ├─ run_discovery.py        # finds “latest run per tool” (supports v1 + v2 layouts)
│     ├─ analyze_suite.py        # cross-tool suite metrics (location/taxonomy agreement)
│     ├─ gt_scorer.py            # GT scoring (writes gt/gt_score.* when used)
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
│  ├─ io.py                      # canonical JSON + file IO helpers
│  └─ core.py                    # orchestration helpers / legacy re-exports
│  │
│  │  Canonical shared normalization layer
│  ├─ normalize/
│  │  ├─ common.py               # schema builders (repo, scan metadata)
│  │  ├─ extractors.py           # shared extraction (location, tags, CWE, text)
│  │  └─ classification.py       # CWE / OWASP resolution and mapping logic
│  │
│  │  Compatibility shims (forwarding modules only)
│  │  - kept so older imports don’t break after refactors
│  ├─ normalize_common.py
│  ├─ normalize_extractors.py
│  └─ classification_resolver.py
│  │
│  │  Tool-specific packages (each tool isolated)
│  ├─ semgrep/
│  │  ├─ __init__.py             # execute(...)
│  │  ├─ runner.py               # runs semgrep; writes raw artifacts
│  │  └─ normalize.py            # raw -> normalized (uses tools/normalize/*)
│  ├─ snyk/
│  ├─ sonar/
│  └─ aikido/
│
├─ schemas/
│  └─ bq/
│     └─ v1/                     # BigQuery table schema JSON (used by export mode)
│        ├─ suites.schema.json
│        ├─ cases.schema.json
│        ├─ tool_runs.schema.json
│        └─ findings.schema.json
│
├─ scripts/
│  ├─ make_worktrees.sh          # create git worktrees for branch-per-case suites
│  └─ smoke_micro_suite.sh       # smoke test helper for micro-suite suites
│
└─ mappings/
   ├─ cwe_to_owasp_top10_mitre.json
   └─ snyk_rule_to_owasp_2021.json
```

---

## Input Layout (cache)

The pipeline uses local folders as **inputs**:

```text
repos/<repo_name>/                 # base clones (URL scans)
repos/worktrees/<repo_name>/<br>/  # worktree checkouts (branch-per-case suites)
```

These are caches. They are safe to delete and should never be committed.

The CLI does **not** automatically generate worktrees. Use `scripts/make_worktrees.sh` (or your own tooling) to prepare them.

---

## Filesystem Layout (Outputs)

This repo supports **two output layouts** for scan results:

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
    export/<schema_version>/    # optional: JSONL tables for warehouse ingestion
      suites.jsonl
      cases.jsonl
      tool_runs.jsonl
      findings.jsonl
      export_manifest.json
```

**Why v2 exists:** it’s easier to browse, and it’s much easier to ingest into a DB because
`suite.json`, `case.json`, and `run.json` provide stable IDs and pointers.

### v1 (legacy)

Used when running scanners directly with `--output-root runs/<tool>` or when you pass `--no-suite`.

```text
runs/<tool>/<repo_name>/<run_id>/
  <repo_name>.normalized.json
  <repo_name>.json | <repo_name>.sarif
  metadata.json
```

---

## Data layers (Bronze / Silver / Gold)

This repo intentionally separates “raw truth” from “curated” outputs:

- **Bronze (raw):** `raw.json` / `raw.sarif`, scanner logs, `metadata.json`, and `run.json`  
  (These are immutable snapshots of what happened.)

- **Silver (normalized):** `normalized.json`  
  (Typed, standardized, cross-tool contract used by analysis and export.)

- **Gold (analytics):** `analysis/` and `gt/` outputs  
  (Derived metrics, joins, aggregations, and scoring.)

- **Warehouse export (optional):** `export/<schema_version>/*.jsonl`  
  (Append-only, stable table-shaped views of the suite for ingestion.)

---

## Process Flow (End-to-End)

```text
                 +--------------------------+
                 |        sast_cli.py       |
                 |  (choose mode & inputs)  |
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
| tools/<tool>/      |  | tools/<tool>/     |   | tools/<tool>/      |  | tools/<tool>/     |
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
                 |     + case.json + suite.json for lineage/joins     |
                 +---------------------------+---------------------- +
                                             |
                           (optional) export |
                                             v
                 +--------------------------------------------------+
                 |              pipeline/export/*                     |
                 | - reads suite/case/run/normalized artifacts        |
                 | - emits JSONL tables under export/<schema_version> |
                 +--------------------------------------------------+
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
