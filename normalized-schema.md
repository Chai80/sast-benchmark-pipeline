# Normalized findings schema

This pipeline normalizes scanner-specific outputs (Semgrep, SonarCloud/SonarScanner, Snyk Code, Aikido) into a **single JSON format** so you can compare tools on the same target repo.

This document describes the **current on-disk shape** produced by the pipeline, plus a few **backwards-compatible adjustments** to make the schema easier to reason about and extend.

---

## Versioning

- `schema_version` is a string.
- **Current**: `1.1` (as emitted by the scripts today).
- **Documented here**: `1.2` (a documentation + compatibility update):
  - Does **not** break existing outputs.
  - Clarifies optional fields and tool-specific enrichment blocks.
  - Treats `run_metadata` as first-class (it already exists in outputs).
  - Clarifies that per-finding `metadata` is **optional/denormalized** (it exists today, but consumers shouldn’t *require* it).

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
| `tool_version` | string | ✅ | Version string reported by the scanner wrapper/script. |
| `target_repo` | object | ✅ | Repo identity + commit info (see below). |
| `scan` | object | ✅ | Run identity + timings + file paths (see below). |
| `run_metadata` | object | ⭕️ | Full contents of `metadata.json` embedded for convenience. Shape is tool-specific but usually includes commit + timing + command. |
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
| `scan_date` | string | ✅ | Timestamp when the run was executed / recorded. |
| `command` | string\|null | ⭕️ | Command used to invoke the scanner (reproducibility). |
| `raw_results_path` | string | ✅ | Where the raw vendor JSON is stored for this run. |
| `scan_time_seconds` | number\|null | ⭕️ | Runtime of scan command (if measured). |
| `exit_code` | integer\|null | ⭕️ | Exit code from the scan command (0/1 success-ish; tool-specific). |
| `metadata_path` | string | ✅ | Relative path to `metadata.json` inside the run directory. |
| `log_path` | string\|null | ⭕️ | Some tools (notably Sonar) may include a log path in run metadata; you *may* surface it here later for consistency. |

**Why both `scan` and `run_metadata`?**  
- `scan` is the *stable, minimal contract* needed to identify the run.  
- `run_metadata` is a convenient embedded copy of the full per-run `metadata.json` (which may vary per tool).

---

## Findings

`findings[]` is the main payload: **one element per issue/finding**.

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
| `rule_id` | string\|null | ✅ | Vendor rule identifier (Semgrep check_id, Sonar rule key, Snyk ruleId, etc.). |
| `title` | string\|null | ✅ | Human-readable message/title. |
| `severity` | string\|null | ⭕️ | **Normalized** severity. Current pipeline uses: `HIGH`, `MEDIUM`, `LOW` (or `null` if unknown). |
| `file_path` | string\|null | ⭕️ | Path within repo. |
| `line_number` | integer\|null | ⭕️ | Start line (1-indexed). |
| `end_line_number` | integer\|null | ⭕️ | End line (1-indexed). |
| `line_content` | string\|null | ⭕️ | Best-effort source snippet (usually the start line). |
| `vendor` | object\|null | ⭕️ | Tool-specific details (see below). |

### Classification fields (optional)

These fields exist to make analysis easier *without* having to parse vendor raw objects.

| Field | Type | Required | Notes |
|---|---:|:---:|--|
| `cwe_id` | string\|null | Single CWE (e.g. `"CWE-89"`). Present when the tool supplies exactly one or we pick a primary. |
| `cwe_ids` | array<string> |Multiple CWEs (primarily from Sonar rule enrichment). If present, `cwe_id` is typically the first entry. |
| `vuln_class` | string\|null | A human rule/category name (Sonar: rule `name` from `/api/rules/show`). |
| `owasp_top_10_2017` | object\|null | OWASP Top 10 2017 mapping (see structure below). |
| `owasp_top_10_2021` | object\|null | OWASP Top 10 2021 mapping (see structure below). |
| `issue_type` | string\|null | Optional normalized “kind” (e.g. Sonar `VULNERABILITY`/`BUG`/`CODE_SMELL`). Recommended addition for readability, not required. |

#### OWASP block structure

When present, the OWASP fields follow this structure:

```json
"owasp_top_10_2021": {
  "codes": ["A03"],
  "categories": ["A03:2021-Injection"]
}
```

- `codes` is the short OWASP code list (e.g. `["A03"]`).
- `categories` is the same list but with human-readable labels.

**Important:** most findings will **not** have OWASP mapping. For Sonar, OWASP mappings come from rule metadata (`securityStandards`) and are typically present only for security rules.

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

Some existing outputs include a `metadata` object inside every finding:

```json
"metadata": {
  "tool": "sonar",
  "tool_version": "...",
  "target_repo": { ...same as top-level... },
  "scan": { ...same as top-level... }
}
```

This is **pure duplication** of top-level fields, useful only if you want each finding to stand alone as a “row”.

**In schema v1.2:**
- Consumers should treat `finding.metadata` as **optional**.
- Producers may keep it for convenience, but it is not required for correct parsing.

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

This block is informational and helps you debug enrichment coverage.

---

## Summary of schema adjustments vs the older doc

Compared to the older `normalized-schema.md` in the repo, this document updates/clarifies:

1. **`run_metadata` is documented** as a first-class top-level field (it already exists in current outputs).
2. **`scan` documents runtime + exit code** (`scan_time_seconds`, `exit_code`) which were missing in the old doc but are in the scripts.
3. **Optional classification keys** are documented (`cwe_ids`, `vuln_class`, OWASP blocks), matching the Sonar enrichment behavior.
4. **Per-finding `metadata` is treated as optional** (recommended to avoid requiring duplicated data downstream).
5. Calls out a future-compatible way to shrink files: store a vendor pointer instead of embedding full `raw_result`.

