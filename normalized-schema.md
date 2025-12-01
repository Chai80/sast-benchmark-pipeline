## Normalized JSON schema

Each tool has its own native format (SARIF, REST API JSON, etc).  
We normalize them into a **common structure** so we can compare tools directly.

---

### Understanding the Schema 

Each normalized JSON file is **one scan** of **one repo** by **one tool**.

Inside the file there are 3 main parts:

1. **Scan header** (top level + `target_repo` + `scan`)
   - which tool ran (`tool`, `tool_version`)
   - which repo & commit (`target_repo`)
   - when and how it ran (`scan` → `run_id`, `scan_date`, `command`)

2. **Findings list** (`findings[]`)
   - one object per issue the tool reported
   - always has: `finding_id`, `severity`, `rule_id`, file + line, and a human-readable `title`

3. **Vendor details** (`vendor.raw_result`)
   - the original tool-specific JSON for that finding
   - we don’t throw away anything; we just wrap it in a common envelope

If you imagine this as tables:

- Table **Scan** → 1 row  
- Table **Findings** → many rows linked to that scan

---

### 1. Conceptual model

At a high level, each JSON file represents **one tool run** on **one repo**:

```text
+---------------------------+
|   Tool run (top level)    |
+---------------------------+
| schema_version            |
| tool, tool_version        |
| target_repo { ... }       |
| scan { ... }              |
| findings [ ... ]          |
+---------------------------+
               |
               | one-to-many
               v
+---------------------------+
|         Finding           |
+---------------------------+
| finding_id                |
| cwe_id, rule_id           |
| severity                  |
| file_path, line_number    |
| line_content              |
| vendor.raw_result { ... } |
+---------------------------+
```

You can think of it as a small pair of tables:

- **One** scan (per tool, per repo, per run)  
- **Many** findings attached to that scan

---

### 2. Top‑level fields

Every normalized JSON file has this top-level structure:

```json
{
  "schema_version": "1.0",
  "tool": "snyk",
  "tool_version": "1.1301.0",
  "target_repo": { ... },
  "scan": { ... },
  "findings": [ ... ]
}
```

| Field            | Type          | Description                                                               |
| ---------------- | ------------- | ------------------------------------------------------------------------- |
| `schema_version` | string        | Version of this normalized schema (`"1.0"` for now).                      |
| `tool`           | string        | Short name of the scanner (`"semgrep"`, `"sonar"`, `"snyk"`, `"aikido"`). |
| `tool_version`   | string        | Version string reported by the scanner.                                   |
| `target_repo`    | object        | Metadata about the repo that was scanned (see below).                     |
| `scan`           | object        | Metadata about this particular run/command.                               |
| `findings`       | array<object> | List of normalized findings (one element per issue).                      |

---

### 3. `target_repo`: what did we scan?

These fields describe **which repository** and **which commit** this scan ran on.

```json
"target_repo": {
  "name": "juice-shop",
  "url": "https://github.com/juice-shop/juice-shop.git",
  "commit": "ded6fc5f7ed4...",
  "commit_author_name": "Björn Kimminich",
  "commit_author_email": "github.com@kimminich.de",
  "commit_date": "2025-11-26T11:38:38+01:00"
}
```
| Field                 | Type   | Description                      |
| --------------------- | ------ | -------------------------------- |
| `name`                | string | Repo name (derived from URL).    |
| `url`                 | string | Git remote URL used in the scan. |
| `commit`              | string | Git SHA that was scanned.        |
| `commit_author_name`  | string | Author of that commit.           |
| `commit_author_email` | string | Author email.                    |
| `commit_date`         | string | ISO 8601 author date.            |

### 4. `scan`: how did we run the tool?

These fields describe **how and when** the scan was run, and where to find raw outputs.

```json
"scan": {
  "run_id": "2025113004",
  "scan_date": "2025-11-30T21:03:34.518761",
  "command": "snyk code test --json-file-output runs/snyk/2025113004/juice-shop.json",
  "raw_results_path": "runs/snyk/2025113004/juice-shop.json",
  "metadata_path": "metadata.json"
}
```
| Field              | Type   | Description                                                     |
| ------------------ | ------ | --------------------------------------------------------------- |
| `run_id`           | string | Run directory ID (`YYYYMMDDNN`).                                |
| `scan_date`        | string | Timestamp when this JSON was generated.                         |
| `command`          | string | Full CLI command used to run the scanner (for reproducibility). |
| `raw_results_path` | string | Where the original vendor JSON is stored on disk.               |
| `metadata_path`    | string | Path to the per-run `metadata.json`.                            |

### 5. `findings[]`: the actual issues

Each element of `findings` is **one normalized issue**:

```json
{
  "finding_id": "snyk:javascript/Sqli:routes/search.ts:23",
  "cwe_id": "CWE-89",
  "rule_id": "javascript/Sqli",
  "title": "Unsanitized SQL query built from user input.",
  "severity": "HIGH",
  "file_path": "routes/search.ts",
  "line_number": 23,
  "end_line_number": 23,
  "line_content": "db.query(`SELECT * ... ${req.query.id}`)",
  "vendor": {
    "raw_result": { "... full Snyk object ..." }
  }
}
```

| Field             | Type         | Description                                                        |
| ----------------- | ------------ | ------------------------------------------------------------------ |
| `finding_id`      | string       | Stable identifier (`<tool>:<rule_id>:<file_path>:<line>`).         |
| `cwe_id`          | string|null  | CWE identifier if known (`"CWE-89"`, etc.).                        |
| `rule_id`         | string       | Vendor’s rule identifier (e.g. `javascript/Sqli`).                 |
| `title`           | string       | Human‑friendly description of the issue.                           |
| `severity`        | string|null  | Normalized severity (`HIGH`, `MEDIUM`, `LOW`).                     |
| `file_path`       | string|null  | File path within the repo.                                         |
| `line_number`     | integer|null | First line of the issue.                                           |
| `end_line_number` | integer|null | Last line (or same as start).                                      |
| `line_content`    | string|null  | Source code line at `line_number` (for context).                   |
| `vendor`          | object       | Tool‑specific data; we store the original JSON under `raw_result`. |

The vendor.raw_result object contains whatever the original scanner produced (e.g. full Snyk SARIF result). You can ignore it for KPIs and dashboards, and only use it when you need deep tool-specific context.
