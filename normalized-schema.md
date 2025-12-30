# Normalized Findings Schema

> **Docs:** [README](README.md) · [Architecture](ARCHITECTURE.md)


This pipeline normalizes scanner-specific outputs (Semgrep, SonarCloud/SonarScanner, Snyk Code, Aikido) into a **single JSON format** so you can compare tools on the same target repo.

This document describes the **on-disk shape** of one normalized run output (one tool × one repo × one run), and clarifies a few **compatibility rules** that make cross-tool analysis reliable.

> **Scope note:** This schema describes the *normalized run artifact* (`<repo>.normalized.json`).  
> Derived analysis artifacts (e.g., “unique hotspots by file”) are documented briefly at the end and live under `runs/analysis/`.

---

## Versioning

- `schema_version` is a string.
- **Current emitted by scripts**: `1.1` (historical runs may be `"1.1"`).
- **Documented here**: `1.2` (documentation + backwards-compatible clarifications):
  - Clarifies **file path semantics** and recommended normalization for comparisons.
  - Clarifies **vendor vs canonical** classification fields (OWASP Top 10).
  - Treats `run_metadata` as a first-class convenience field (it already exists in some outputs).
  - Clarifies that per-finding `metadata` is optional/denormalized.

No changes described here should break consumers that already parse `1.1` outputs.

---

## File-level model

**One normalized JSON file == one tool run on one target repo.**

Top-level shape:

```json
{
  "schema_version": "1.2",
  "tool": "sonar",
  "tool_version": "SonarScanner CLI 7.3.0.5189",

  "target_repo": { ... },
  "scan": { ... },

  "run_metadata": { ... },

  "sonar_rules_enrichment": { ... },

  "findings": [ ... ]
}
```

### Top-level fields

| Field | Type | Required | Notes |
|---|---:|:---:|---|
| `schema_version` | string | ✅ | Schema version string (e.g. `"1.1"`, `"1.2"`). |
| `tool` | string | ✅ | Scanner short name: `semgrep`, `sonar`, `snyk`, `aikido`. |
| `tool_version` | string | ✅ | Version string reported by the wrapper/script. |
| `target_repo` | object | ✅ | Repo identity + commit info (see below). |
| `scan` | object | ✅ | Run identity + timings + file paths (see below). |
| `run_metadata` | object | ⭕️ | Embedded copy of the full per-run `metadata.json` (tool-specific). |
| `sonar_rules_enrichment` | object | ⭕️ | Sonar-only summary block when rule enrichment was performed. |
| `findings` | array<object> | ✅ | List of normalized findings. |

---

## `target_repo`

Describes **what you scanned**:

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
| `commit` | string | ⭕️ | Git SHA scanned (may be `"unknown"` if git info failed). |
| `commit_author_name` | string\|null | ⭕️ | From `git show -s`. |
| `commit_author_email` | string\|null | ⭕️ | From `git show -s`. |
| `commit_date` | string\|null | ⭕️ | ISO 8601 author date. |

---

## `scan`

Describes **how and when you scanned**:

```json
"scan": {
  "run_id": "2025122201",
  "scan_date": "2025-12-22T17:13:29.903427",
  "command": "sonar-scanner ...",
  "raw_results_path": "runs/sonar/juice-shop/2025122201/juice-shop.json",

  "scan_time_seconds": 342.2597,
  "exit_code": 3,

  "metadata_path": "metadata.json"
}
```

| Field | Type | Required | Notes |
|---|---:|:---:|---|
| `run_id` | string | ✅ | Run directory ID (`YYYYMMDDNN`). |
| `scan_date` | string | ✅ | Timestamp when the run was executed/recorded. |
| `command` | string\|null | ⭕️ | Command used to invoke the scanner (reproducibility). |
| `raw_results_path` | string | ✅ | Where the raw vendor output is stored for this run. |
| `scan_time_seconds` | number\|null | ⭕️ | Runtime of scan command (if measured). |
| `exit_code` | integer\|null | ⭕️ | Exit code from the scan command (tool-specific). |
| `metadata_path` | string | ✅ | Relative path to `metadata.json` inside the run directory. |
| `log_path` | string\|null | ⭕️ | Optional: log path (some tools may surface this later for consistency). |

**Why both `scan` and `run_metadata`?**  
- `scan` is the stable minimal contract needed to identify the run.
- `run_metadata` is a convenient embedded copy of the full per-run metadata.

---

## Findings

`findings[]` is the main payload: **one element per tool finding**.

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

  "vendor": { "raw_result": { "... tool-specific ..." } }
}
```

| Field | Type | Required | Notes |
|---|---:|:---:|---|
| `finding_id` | string | ✅ | Stable-ish identifier. Convention: `<tool>:<rule_id>:<file_path>:<line>`. |
| `rule_id` | string\|null | ✅ | Vendor rule identifier (Semgrep `check_id`, Sonar rule key, Snyk `ruleId`, etc.). |
| `title` | string\|null | ✅ | Human-readable message/title. |
| `severity` | string\|null | ⭕️ | Normalized severity (`HIGH`, `MEDIUM`, `LOW`) or `null`. |
| `file_path` | string\|null | ⭕️ | Best-effort path to the file within the repo (see “File path semantics”). |
| `line_number` | integer\|null | ⭕️ | Start line (1-indexed). |
| `end_line_number` | integer\|null | ⭕️ | End line (1-indexed). |
| `line_content` | string\|null | ⭕️ | Best-effort snippet (usually the start line). |
| `vendor` | object\|null | ⭕️ | Tool-specific details (see below). |

---

## File path semantics (important for cross-tool comparisons)

`file_path` is **best-effort** and may vary across tools and runs. In particular, some tools may include a repo prefix (e.g., `juice-shop/routes/...`) while others emit repo-relative paths (`routes/...`).

### Recommended normalization for comparisons

When building cross-tool metrics (e.g., “unique hotspots by file”), normalize paths at **analysis time** using these rules:

1. Convert `\` → `/`
2. Strip leading `./`
3. Strip leading `/`
4. Collapse duplicate slashes (`//` → `/`)
5. If the path begins with `{target_repo.name}/`, strip that prefix

This ensures the same file is comparable across tools.

### Optional future field (backwards-compatible)

If you later want normalization inside the normalized JSON (rather than only at analysis-time), store both:

- `file_path_raw` (string\|null): original path as emitted by the tool parser
- `file_path` (string\|null): normalized repo-relative path

This preserves provenance while keeping `file_path` comparison-ready.

---

## Classification fields (optional but strongly recommended)

These fields exist to make analysis easier without having to parse vendor raw objects.

| Field | Type | Required | Notes |
|---|---:|:---:|--|
| `cwe_id` | string\|null | ⭕️ | Single CWE (e.g. `"CWE-89"`). |
| `cwe_ids` | array<string> | ⭕️ | Multiple CWEs (often from Sonar rule enrichment). |
| `vuln_class` | string\|null | ⭕️ | Human rule/category name (e.g., Sonar rule name). |
| `issue_type` | string\|null | ⭕️ | Optional normalized kind (e.g., Sonar `VULNERABILITY`/`BUG`/`CODE_SMELL`). |
| `owasp_top_10_2017_vendor` | object\|null | ⭕️ | OWASP 2017 mapping reported by the tool (if tool provides). |
| `owasp_top_10_2017_canonical` | object\|null | ⭕️ | OWASP 2017 mapping derived from CWE→OWASP mapping (canonical). |
| `owasp_top_10_2021_vendor` | object\|null | ⭕️ | OWASP 2021 mapping reported by the tool (if tool provides). |
| `owasp_top_10_2021_canonical` | object\|null | ⭕️ | OWASP 2021 mapping derived from CWE→OWASP mapping (canonical). |
| `owasp_top_10_2017` | object\|null | ⭕️ | Compatibility alias (prefer explicit `*_vendor` and `*_canonical`). |
| `owasp_top_10_2021` | object\|null | ⭕️ | Compatibility alias (prefer explicit `*_vendor` and `*_canonical`). |

### Vendor vs canonical (do not blur)

- **Vendor** OWASP fields (`*_vendor`) represent what the scanner itself claims.
- **Canonical** OWASP fields (`*_canonical`) represent a tool-agnostic mapping derived from CWE (e.g., MITRE CWE→OWASP Top 10 mapping).

To keep comparisons honest, avoid mixing these sources silently:
- Cross-tool metrics should prefer **canonical** (tool-agnostic).
- Vendor fields are best for “what the tool says” auditing/debugging.

### OWASP block structure

When present, OWASP blocks follow:

```json
"owasp_top_10_2021_canonical": {
  "codes": ["A03"],
  "categories": ["A03:2021-Injection"]
}
```

- `codes`: short OWASP code list (e.g. `["A03"]`)
- `categories`: codes with human-readable labels

---

## Optional: finding kind (recommended future addition)

Some tools may report non-SAST issues (e.g., dependency/SCA, secrets). To make filtering non-spaghetti in analysis, consider adding an optional normalized field:

- `finding_kind`: one of:
  - `sast` (code issue with file/line)
  - `sca` (dependency/package issue)
  - `secrets` (leaked secret)
  - `config` (configuration issue)
  - `other`

This is **optional** and backwards-compatible. In the meantime, analysis can approximate this using heuristics (e.g., `line_number != null` often implies code).

---

## `vendor`

`vendor.raw_result` contains the original tool finding object (Semgrep result entry, Sonar issue object, Snyk SARIF result object, etc.).

```json
"vendor": {
  "raw_result": { "... the original tool JSON object ..." }
}
```

This is useful for debugging and future enrichments, but it can make files large. If size becomes a problem, a compatible future adjustment is to store:

- `vendor.raw_result` (optional, omitted by default), and
- `vendor.raw_pointer` (required), e.g. `{ "path": "<raw_results_path>", "index": 123 }`.

---

## Per-finding `metadata` (denormalized / optional)

Some outputs include a `metadata` object inside each finding:

```json
"metadata": {
  "tool": "sonar",
  "tool_version": "...",
  "target_repo": { ...same as top-level... },
  "scan": { ...same as top-level... }
}
```

This duplicates top-level fields. In schema v1.2:

- Consumers should treat `finding.metadata` as **optional**.
- Producers may keep it for convenience, but it is not required.

---

## Sonar-only enrichment summary

When Sonar rule classification enrichment runs, you’ll see:

```json
"sonar_rules_enrichment": {
  "source": "api/rules/show",
  "host": "https://sonarcloud.io",
  "organization": "chai80",
  "rules_with_classification": 91,
  "findings_enriched": 757
}
```

---

## Derived analysis artifacts (not part of the normalized schema)

The analysis layer reads normalized run artifacts and produces derived reports, for example:

### Unique hotspots by file

Signature:
```
(normalized_file_path, OWASP_2021_canonical_code)
```

Typical output location:
```
runs/analysis/<repo_name>/latest_hotspots_by_file.json
```

These derived reports are safe to delete and recompute and are not subject to the normalized schema versioning.
