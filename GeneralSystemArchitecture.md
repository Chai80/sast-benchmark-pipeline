# General System Architecture

This document explains the **fresh architecture** for suite runs after introducing
an explicit **Resolver** step.

The key idea is simple:

> **Suite inputs are just "work orders".**
> The **run folder under `runs/`** is the only source of truth for what actually
> happened, and it must contain a canonical manifest.

---

## What we had before

The system effectively had **two competing sources of truth**:

* **Suite inputs** (CSV work orders, suite `.py` files, worktrees discovery)
* **Suite outputs** (`runs/suites/<suite_id>/...`)

Because the pipeline didn't have a single “resolution boundary”, different layers
re-derived IDs and paths.

```text
            (portable-ish)               (machine-specific)
  examples/suite_inputs/<workload>.py      inputs/suite_inputs/*.csv / worktrees root
              |                         |
              |                         |
              +-----------+-------------+
                          |
                          v
                 [ Execution / Orchestration ]
                 - picks cases
                 - derives case ids
                 - decides output dirs
                          |
                          v
            runs/suites/<suite_id>/...   (manifests written later)

Spaghetti symptoms:
  - different code paths "re-derive" case_id (underscore vs hyphen)
  - CSVs contain absolute paths -> not portable to CI/other machines
  - analysis/debugging sometimes relies on inputs instead of manifests
  - hard to know what the *canonical* case list for a run really was
```

---

## The new architecture

We add a dedicated **Resolver** step.

The resolver:

* takes any suite input (suite file, CSV, discovered worktrees)
* normalizes + validates it into a single canonical plan
* writes that plan to `runs/suites/<suite_id>/suite.json` **before execution**

After that, the rest of the pipeline should rely on **`runs/` manifests**, not
on suite input files.

```text
   Suite inputs (work orders)
   -------------------------
   - suite .py (portable definition)
   - CSV (local/CI work order)
   - worktrees discovery
              |
              v
        [ Resolver boundary ]
        - resolve repo_key -> repo_url
        - validate repo_url/repo_path
        - normalize case ids
        - ensure suite/case dirs exist
        - WRITE canonical suite.json plan
              |
              v
   runs/suites/<suite_run_id>/
     suite.json   <-- SOURCE OF TRUTH (plan + per-case execution summary)
     cases/<case_id>/
       case.json  <-- SOURCE OF TRUTH for that case (lineage + tool runs)
       tool_runs/<tool>/<run_id>/
         run.json
         raw.*
         normalized.json
       analysis/*
       gt/*
              |
              v
   [ Execution ]
   - run tools using the resolved CaseSpec
   - write run.json / case.json
   - update suite.json execution summary (best-effort)
              |
              v
   [ Analysis ]
   - consumes normalized.json
   - writes analysis artifacts under the case directory
```

### Why this prevents spaghetti

With a resolver boundary, there is only **one place** where we decide:

* what the canonical case IDs are
* what repos/paths are scanned
* what suite run directory is used

Everything downstream reads from a **single manifest** in `runs/`, instead of
re-deriving identifiers differently in multiple modules.

---

## Implementation note (where to look)

* Resolver implementation: `pipeline/suite_resolver.py`
* Suite orchestration entrypoint: `sast_cli.py` (`run_suite_mode`)
* Suite layout helpers (dirs + incremental suite.json updates): `pipeline/bundles.py`
