# Normalized Findings Contract (`normalized.json`)

> **Docs:** [README](README.md) · [Architecture](ARCHITECTURE.md)

This repo runs multiple security scanners (Semgrep, SonarCloud/SonarScanner, Snyk Code, Aikido) and produces **comparable outputs** per tool run.

This document defines the **normalized run artifact**: a single JSON file that represents:

> **one tool × one target repo × one run**

The normalized artifact is typically named:

- `normalized.json` (suite/case layout, preferred), or
- `<repo_name>.normalized.json` (legacy layout)

Derived analytics (agreement matrices, hotspot packs, triage queues, GT scoring, exports) are **not** part of this schema. Those live under `analysis/`, `gt/`, and `export/`.

---

## Why we have a normalized contract (design rationale)

Different scanners:
- emit different formats (tool JSON vs SARIF),
- use different severity scales,
- disagree on how to represent locations (file path formats, missing line ranges),
- attach different classification metadata (CWE, OWASP) or none at all.

To make cross-tool analysis possible without “special casing every tool everywhere”, we separate outputs into **layers**:

```text
Bronze: raw.* + logs + metadata.json + run.json  (immutable “what the tool said”)
  |
  v
Silver: normalized.json                           (tool-agnostic contract)
  |
  v
Gold: analysis/* + gt/* (+ optional export/*)     (derived/aggregated outputs)
```

### Key decisions (and why)

1) **Keep raw outputs intact (Bronze)**
- Raw tool outputs are the source of truth for debugging.
- Normalization is best-effort; raw lets you re-normalize later if rules change.

2) **Normalize only what’s needed for comparisons (Silver)**
- Normalized files are intentionally **smaller and more uniform** than raw.
- We standardize the fields analysis needs (location, severity, classification, identifiers) and keep the rest in `vendor.raw_result` (optional).

3) **Store both “vendor” and “canonical” classification**
- Tools may claim OWASP categories directly. That’s valuable, but not comparable across tools.
- For apples-to-apples analysis we derive a **canonical** OWASP mapping from CWE using shared mappings.
- We keep them separate so we never silently blend sources.

4) **Prioritize determinism**
- Normalized outputs are stabilized (sorted, deterministic IDs) so diffs between runs are meaningful.

5) **Allow partial/missing data**
- Some tools don’t provide CWE, or a precise location.
- The schema uses `null` for unknowns rather than guessing.

---

## On-disk layouts (where `normalized.json` lives)

This repo supports two filesystem layouts. Both write the **same schema**.

### v2 (suite/case layout, preferred)

```text
runs/suites/<suite_id>/cases/<case_id>/tool_runs/<tool>/<run_id>/
  normalized.json
  raw.json | raw.sarif
  metadata.json
  run.json
  logs/...                (optional)
```

### v1 (legacy)

```text
runs/<tool>/<repo_name>/<run_id>/
  <repo_name>.normalized.json
  <repo_name>.json | <repo_name>.sarif
  metadata.json
```

---

## Versioning & evolution rules

- `schema_version` is a **string** (e.g., `"1.1"`).
- **Current emitted by the pipeline:** `1.1`

### Backwards-compatibility contract

To keep analysis and ingestion stable:

**Non-breaking changes (allowed in a minor bump):**
- add a new optional top-level field
- add a new optional field inside a finding
- add a new enum value if consumers treat unknown values safely

**Breaking changes (require a major bump):**
- rename/remove fields
- change types (e.g., `line_number` int → string)
- change the meaning/semantics of an existing field

> Implementation note: the repo also supports optional “warehouse export” schemas (JSONL tables).
> Those export schemas are versioned separately from this normalized schema.

---

## File-level model

**One normalized JSON file == one tool run on one target repo.**

Top-level shape:

```json
{
  "schema_version": "1.1",
  "tool": "sonar",
  "tool_version": "SonarScanner CLI 7.3.0.5189",

  "target_repo": { },
  "scan": { },

  "run_metadata": { },

  "findings": [ ]
}
```

### Top-level fields

| Field | Type | Required | Notes |
|---|---:|:---:|---|
| `schema_version` | string | ✅ | Contract version string. |
| `tool` | string | ✅ | Scanner short name: `semgrep`, `sonar`, `snyk`, `aikido`. |
| `tool_version` | string | ✅ | Version string reported by the wrapper/script (best-effort). |
| `target_repo` | object | ✅ | Repo identity + commit info (below). |
| `scan` | object | ✅ | Run identity + timings + artifact pointers (below). |
| `run_metadata` | object | ⭕️ | Embedded copy of `metadata.json` (tool-specific). |
| `findings` | array<object> | ✅ | List of normalized findings. |
| `*_enrichment` | object | ⭕️ | Tool-specific optional blocks (e.g., Sonar rule enrichment summary). |

**Rule:** Consumers must ignore unknown top-level fields (forward-compatible).

---

## `target_repo` (what you scanned)

```json
"target_repo": {
  "name": "juice-shop",
  "url": "https://github.com/juice-shop/juice-shop.git",
  "commit": "ff5ba3300a331e9712eabe073409e00a4b1e8aa1",
  "commit_author_name": "Bjoern Kimminich",
  "commit_author_email": "bjoern.kimminich@kuehne-nagel.com",
  "commit_date": "2025-12-01T11:11:50+01:00"
}
```

| Field | Type | Required | Notes |
|---|---:|:---:|---|
| `name` | string | ✅ | Derived repo name (usually from URL). |
| `url` | string | ✅ | Git remote URL used. |
| `commit` | string\|null | ⭕️ | Git SHA scanned (may be `null` or `"unknown"` if git info failed). |
| `commit_author_name` | string\|null | ⭕️ | From `git show -s` (best-effort). |
| `commit_author_email` | string\|null | ⭕️ | From `git show -s` (best-effort). |
| `commit_date` | string\|null | ⭕️ | ISO 8601 author date (best-effort). |

---

## `scan` (how and when you scanned)

```json
"scan": {
  "run_id": "2026010901012903",
  "scan_date": "2026-01-09T01:29:09.768696+00:00",
  "command": "semgrep --json --config auto ...",
  "raw_results_path": "raw.json",
  "metadata_path": "metadata.json",
  "scan_time_seconds": 5.2453,
  "exit_code": 0,
  "log_path": null
}
```

| Field | Type | Required | Notes |
|---|---:|:---:|---|
| `run_id` | string | ✅ | Run directory ID (sortable timestamp-based). |
| `scan_date` | string | ✅ | ISO 8601 timestamp recorded at run time. |
| `command` | string\|null | ⭕️ | Exact tool invocation used (reproducibility; may be omitted for API-based scans). |
| `raw_results_path` | string | ✅ | Raw vendor output filename/path (usually relative within the run dir). |
| `metadata_path` | string | ✅ | Relative path to `metadata.json` within the run directory. |
| `scan_time_seconds` | number\|null | ⭕️ | Runtime of scan command (if measured). |
| `exit_code` | integer\|null | ⭕️ | Exit code (tool-specific conventions). |
| `log_path` | string\|null | ⭕️ | Optional path to log output (often used by Sonar). |

**Why both `scan` and `run_metadata`?**
- `scan` is the stable minimal contract needed to identify the run and locate artifacts.
- `run_metadata` is a convenient embedded copy of the full per-run metadata used for debugging/enrichment.

---

## `run.json` (lineage pointer; v2 layout)

In the suite/case layout, each tool run folder also includes `run.json`. This is not part
of `normalized.json`, but it is an important *system* contract: it provides stable IDs and
artifact filenames without relying on directory parsing.

If you are building ingestion or ETL, prefer `run.json` + `case.json` + `suite.json` for lineage.

---

## Findings (`findings[]`)

`findings[]` is the payload: **one element per tool finding**.

### Finding object (core fields)

```json
{
  "finding_id": "sonar:tssecurity:S5334:routes/b2bOrder.ts:23",
  "rule_id": "tssecurity:S5334",
  "title": "Change this code to not dynamically execute code influenced by user-controlled data.",
  "severity": "HIGH",

  "file_path": "routes/b2bOrder.ts",
  "line_number": 23,
  "end_line_number": 23,
  "line_content": "vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })",

  "cwe_id": "CWE-94",
  "owasp_top_10_2021_canonical": { "codes": ["A03"], "categories": ["A03:2021-Injection"] },

  "vendor": { "raw_result": { } }
}
```

| Field | Type | Required | Notes |
|---|---:|:---:|---|
| `finding_id` | string | ✅ | Stable-ish identifier (see below). |
| `rule_id` | string\|null | ✅ | Vendor rule identifier (Semgrep check_id, Sonar key, Snyk ruleId, etc.). |
| `title` | string\|null | ✅ | Human-readable message/title. |
| `severity` | string\|null | ⭕️ | Normalized severity: `CRITICAL|HIGH|MEDIUM|LOW|INFO` (or `null`). |
| `file_path` | string\|null | ⭕️ | Repo-relative path best-effort (see path semantics). |
| `line_number` | integer\|null | ⭕️ | Start line (1-indexed). |
| `end_line_number` | integer\|null | ⭕️ | End line (1-indexed). |
| `line_content` | string\|null | ⭕️ | Best-effort snippet (usually the start line). |
| `issue_type` | string\|null | ⭕️ | Optional normalized kind (e.g., Sonar `VULNERABILITY|BUG|CODE_SMELL`). |
| `cwe_id` | string\|null | ⭕️ | Primary CWE (e.g., `"CWE-89"`). |
| `cwe_ids` | array<string> | ⭕️ | Additional CWEs (best-effort). |
| `owasp_top_10_2017_vendor` | object\|null | ⭕️ | OWASP 2017 mapping claimed by tool (if any). |
| `owasp_top_10_2017_canonical` | object\|null | ⭕️ | OWASP 2017 mapping derived from CWE (canonical). |
| `owasp_top_10_2021_vendor` | object\|null | ⭕️ | OWASP 2021 mapping claimed by tool (if any). |
| `owasp_top_10_2021_canonical` | object\|null | ⭕️ | OWASP 2021 mapping derived from CWE (canonical). |
| `vendor` | object\|null | ⭕️ | Tool-specific details (see below). |
| `metadata` | object\|null | ⭕️ | Optional denormalized copy of run metadata (discouraged; prefer top-level). |

### `finding_id` format (recommendation)

`finding_id` should be deterministic within a run so output diffs are meaningful.

Recommended convention:

```text
<tool>:<rule_id>:<file_path>:<line_number>
```

When line or file is missing, fall back to a hash of tool-provided stable identifiers.

---

## File path semantics (important for comparisons)

`file_path` is **best-effort** and may vary between tools. Common inconsistencies:
- repo prefix vs repo-relative paths
- different separators (`\` vs `/`)
- leading `./` or `/`

**Recommendation:** comparisons should normalize paths at analysis time:

1. Convert `\` → `/`
2. Strip leading `./` and `/`
3. Collapse duplicate slashes
4. If path starts with `{target_repo.name}/`, strip that prefix

> Optional future improvement (backwards-compatible): store both
> `file_path_raw` and normalized `file_path`.

---

## Classification fields: vendor vs canonical

We keep classification as **two parallel views**:

- **Vendor** fields (`*_vendor`) = what the tool claims (may be missing or vendor-specific)
- **Canonical** fields (`*_canonical`) = derived tool-agnostic mapping from CWE using shared tables

This prevents misleading “agreement” metrics where tools *appear* to agree because we forced them into one bucket.

### OWASP block structure

When present, OWASP blocks follow:

```json
"owasp_top_10_2021_canonical": {
  "codes": ["A03"],
  "categories": ["A03:2021-Injection"]
}
```

---

## `vendor` (tool-specific payload)

`vendor.raw_result` contains the original tool finding object (Semgrep result entry, Sonar issue object, Snyk SARIF result entry, etc.):

```json
"vendor": {
  "raw_result": { "... tool-native object ..." }
}
```

This is useful for debugging and future enrichments, but it can make files large.

If file size becomes a problem, a compatible future adjustment is:

- `vendor.raw_result` (optional / omitted by default), and
- `vendor.raw_pointer` (preferred), e.g. `{ "path": "raw.sarif", "index": 123 }`.

---

## Determinism & stable diffs (producer requirements)

To keep diffs meaningful and avoid “noise”:

- findings should be **sorted** deterministically (e.g., by `(file_path, line_number, rule_id, finding_id)`)
- list-like fields (`cwe_ids`, OWASP codes/categories) should be **sorted and de-duplicated**
- avoid including volatile fields inside each finding when possible (timestamps, random IDs)

Implementation lives in the normalization helpers under `tools/normalize/*`.

---

## Consumer guidance (analysis, export, external users)

Consumers should:

- Treat `normalized.json` as the **Silver contract** (stable shape + semantics).
- Ignore unknown fields (forward-compatible).
- Prefer top-level `target_repo` and `scan` over any per-finding `metadata`.
- Use `run.json` / `case.json` / `suite.json` for lineage in suite layout instead of re-deriving IDs from paths.

---

## Producer checklist (scanner adapter authors)

When adding or modifying a tool adapter, ensure each tool run produces:

- Bronze: `raw.json` or `raw.sarif` (+ logs if available) + `metadata.json` + `run.json` (suite layout)
- Silver: `normalized.json` (schema v1.1)
- Fill required fields and use `null` for unknowns
- Keep vendor vs canonical classification separated
- Keep output deterministic

---

## Relationship to export / warehouse ingestion (optional)

`normalized.json` is optimized for traceability and cross-tool comparisons, but it is nested.

For ingestion into warehouses (e.g., BigQuery), the pipeline can emit **append-only JSONL tables**
with stable schemas via export mode (see README). Those table schemas are versioned separately
from this normalized schema.

