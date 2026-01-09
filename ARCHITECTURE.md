# Durinn SAST Benchmark Pipeline — Architecture

Durinn is a **filesystem-first benchmark pipeline**: it runs multiple static/security scanners across one or many codebases, writes **raw tool outputs**, converts them into a **single normalized findings contract**, and then runs **cross-tool analysis** (agreement/hotspots/taxonomy/triage + optional GT scoring).

The design goal is **clean, non-spaghetti automation**:
- **Stable subprocess entrypoints** (`tools/scan_*.py`) so orchestration doesn’t depend on tool internals.
- **Tool adapters are isolated** (`tools/<tool>/…`) so adding/changing a scanner is localized.
- **Normalized JSON is the cross-tool contract** consumed by analysis (tools do parsing; pipeline orchestrates).
- **Manifests + canonical layout helpers** provide reproducibility and “where did this come from?” traceability.

---

## Start here (reading order)

1. `sast_cli.py` — CLI + UX (modes + inputs)
2. `pipeline/orchestrator.py` — high-level coordinator (cases/tools, manifests, errors)
3. `pipeline/core.py` — scanner registry + builds the subprocess commands
4. `sast_benchmark/io/layout.py` + `pipeline/bundles.py` — canonical output paths + suite/case manifests
5. `pipeline/analysis/runner.py` + `pipeline/analysis/framework/*` — stage engine for analysis
6. `tools/scan_semgrep.py` → `tools/semgrep/*` — representative scanner adapter pattern

---

## Architecture at a glance

### Layers / dependency direction

```text
CLI (sast_cli.py)
   |
   v
Orchestration (pipeline/*)  --->  Contracts (sast_benchmark/*)
   |
   | stable subprocess contract: python tools/scan_<tool>.py ...
   v
Tool entrypoints (tools/scan_*.py)  --->  Tool adapters (tools/<tool>/*)
```

Dependency intent (to keep boundaries clear):
- `sast_benchmark/` is foundational (types + layout). It should not depend on `pipeline/` or `tools/`.
- `tools/` may depend on `sast_benchmark/`.
- `pipeline/` may depend on `tools/` + `sast_benchmark/`.
- CLI can depend on everything.

> Known cleanup item: there is still a small legacy import that makes `sast_benchmark` depend on `tools` for run-dir compatibility. Long-term, move that run-id/run-dir helper into `sast_benchmark.io` (or a tiny shared module) to fully enforce the rule above.

### End-to-end flow (suite/benchmark run)

```text
sast_cli.py
  -> pipeline/orchestrator.py
    -> pipeline/core.py (tool -> scan script, build cmd)
      -> tools/scan_<tool>.py (thin shim)
        -> tools/<tool>/execute(): runner writes raw + normalize writes normalized
          -> runs/suites/<suite_id>/cases/<case_id>/tool_runs/<tool>/<run_id>/
    -> (optional) pipeline/analysis/runner.py -> runs/suites/<suite_id>/cases/<case_id>/analysis/*
```

---

## Outputs and contracts

### Data lifecycle (Bronze / Silver / Gold)

```text
Bronze: raw.(json|sarif) + logs + metadata.json + run.json   (immutable)
   |
   v
Silver: normalized.json (schema_version: 1.1)               (cross-tool contract)
   |
   v
Gold: analysis/* + gt/*                                     (derived metrics)
```

### Preferred output layout (v2 suite/case)

```text
runs/suites/<suite_id>/
  suite.json            # suite index
  summary.csv           # one row per case (human-friendly entry point)
  cases/<case_id>/
    case.json           # “ground truth” manifest for this case
    tool_runs/<tool>/<run_id>/
      run.json
      raw.(json|sarif)
      normalized.json
      metadata.json
      logs/...
    analysis/...
    gt/...              # optional scoring artifacts
```

(v1 legacy layout still exists for compat when running tools directly; analysis supports both.)

### Normalized findings contract (schema v1.1)

Every scanner adapter writes `normalized.json` with a consistent structure:
- run metadata (tool + target + command + timestamps + exit code)
- `findings`: list of normalized findings

Each finding includes at minimum:
- `finding_id` (deterministic within a run)
- `rule_id`
- `title`

Common fields used by analysis:
- severity (`HIGH|MEDIUM|LOW` when possible)
- `file_path`, `line_number` (and optional range/text)
- CWE / OWASP classification:
  - vendor view (what tool says)
  - canonical view (derived uniformly from CWE via `mappings/`)

Normalization helpers live in `tools/normalize/*` and are designed for stable diffs (sorted outputs).

---

## Analysis model (stage pipeline)

Analysis is a **stage pipeline** to keep metrics modular:
- `AnalysisContext` is the immutable job packet.
- `ArtifactStore` is the shared output registry/scratchpad.
- Stages register via `@register_stage("name")`.
- Pipelines are ordered lists of stage names.
- Entry point: `pipeline/analysis/runner.run_suite(...)`.

Stages write artifacts under each case’s `analysis/` folder and record outputs in an `analysis_manifest.json`.

---

## Extending the system

### Add a new scanner adapter

1. Add a stable entrypoint: `tools/scan_<tool>.py` (thin argparse wrapper).
2. Implement `tools/<tool>/`:
   - `runner.py` executes the tool and writes raw output
   - `normalize.py` converts raw → `normalized.json` (schema v1.1)
3. Use canonical layout helpers (`sast_benchmark.io.layout.prepare_run_paths(...)`).
4. Register tool in `pipeline/core.py` (tool name -> entrypoint).

### Add a new analysis metric

1. Add a stage in `pipeline/analysis/stages/<name>.py` and register it.
2. Write artifacts + register them in `ArtifactStore`.
3. Add stage to a pipeline list in `pipeline/analysis/framework/pipelines.py`.

---

## Guardrails 

- Pipeline orchestrates; **tools parse/normalize**. No raw tool parsing in `pipeline/`.
- **Stable entrypoints** are the integration boundary: `pipeline` shells out to `tools/scan_*.py`.
- **Layouts are centralized**: don’t hardcode paths; use the layout helpers/manifests.
- **Manifests are ground truth**: downstream jobs should follow `suite.json` / `case.json` / `run.json`.
- Prefer typed dataclasses for cross-module payloads to avoid “dict soup”.
