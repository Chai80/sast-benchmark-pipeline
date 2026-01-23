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
3. `pipeline/execution/run_case.py` + `pipeline/execution/{plan,runner,record}.py` — execution engine (planning + subprocess + receipts)
4. `pipeline/scanners.py` — scanner registry (supported tools, labels, scripts, tracks)
5. `pipeline/core.py` — builds the subprocess commands (`tools/scan_*.py` invocations)
6. `cli/commands/suite.py` + `cli/commands/suite/runbook.py` (`cli/commands/suite/runbook_steps/*`) — suite mode + interactive runbook (resolver boundary + QA triage calibration)
7. `sast_benchmark/io/layout.py` + `pipeline/suites/layout.py` — canonical output paths + suite/case manifests
8. `pipeline/analysis/runner.py` + `pipeline/analysis/framework/*` — stage engine for per-case analysis
9. `pipeline/analysis/qa_calibration_runbook/` + `pipeline/analysis/suite_triage_*` — suite-scoped triage calibration (legacy wrapper: `pipeline/analysis/qa/qa_calibration_runbook.py`)
10. `pipeline/analysis/suite_report/` — suite report builder (legacy wrapper: `pipeline/analysis/suite/suite_report.py`)
11. `pipeline/scoring/gt_scorer.py` + `pipeline/scoring/gt_markers.py` — GT matching + scoring primitives
12. `tools/scan_semgrep.py` → `tools/semgrep/*` — representative scanner adapter pattern


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


### GT catalog compilation (avoids "spaghetti" GT logic)

Suites may author ground-truth (GT) in different ways (YAML catalogs or in-code markers).
During **suite materialization**, the pipeline always produces a canonical artifact:

`runs/suites/<suite_id>/cases/<case_id>/gt/gt_catalog.yaml`

Downstream analysis reads only this artifact, keeping dependencies one-directional:
execution/orchestration -> artifacts -> analysis.

See `docs/GT_COMPILATION.md` for details.
### Suite-scoped analysis artifacts (triage calibration)

Most artifacts are written **per-case** under `cases/<case_id>/analysis/`.

Triage calibration is suite-scoped and writes under:

```text
runs/suites/<suite_id>/analysis/
  _tables/triage_dataset.csv
  triage_calibration.json
  _tables/triage_calibration_report.csv
  _tables/triage_eval_summary.json
  qa_calibration_checklist.txt
  qa_manifest.json     # QA "receipt": inputs + GT tolerance policy + artifact paths

  # Optional (when --gt-tolerance-sweep / --gt-tolerance-auto is used):
  _tables/gt_tolerance_sweep_report.csv
  _tables/gt_tolerance_sweep_tool_stats.csv
  gt_tolerance_sweep.json
  gt_tolerance_selection.json
  _sweeps/gt_tol_<t>/analysis/...
```

Because the calibration JSON is produced at the **suite level**, per-case triage queues
need a second “analysis-only” pass to populate `triage_score_v1`.
The QA helper (`--mode suite --qa-calibration`) runs that second pass automatically.

`qa_manifest.json` is a small, deterministic "receipt" for the QA runbook. It records:
- the effective GT tolerance policy (explicit vs sweep vs auto-select)
- the knobs that affect calibration/eval
- canonical paths to the runbook artifacts
- PASS/FAIL state (exit code + checklist)

This makes CI runs auditable and makes it easy to diff “what changed?” across QA runs.

### Preferred output layout (v2 suite/case)

```text
runs/suites/<suite_id>/
  suite.json            # suite index
  summary.csv           # one row per case (human-friendly entry point)
  replay/               # optional: "replay button" for interactively curated suites
    replay_suite.py     # exports SUITE_RAW; used via --suite-file
    replay_command.txt  # copy/paste helper command (best-effort)
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

### Replay files (optional)

When you build a suite **interactively**, the CLI can optionally write a small Python
**replay file** under `runs/suites/<suite_id>/replay/`. Treat this as a *replay button*:
it captures the curated case list + scanners so you can rerun later without re-answering prompts
(`--suite-file ...`).

If your suite was sourced from `--worktrees-root` or `--cases-from`, you typically do **not**
need a replay file—those inputs are already replayable by rerunning the same command.

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

### Triage scoring + calibration (v1 + v2)

The triage pipeline produces a ranked `triage_queue.csv` per case.

If a suite contains GT and has built `analysis/triage_calibration.json`, the ranking stage will:

1) add a `triage_score_v1` column to the queue (schema is always present; values may be empty),
2) sort primarily by `triage_score_v1` (descending), then fall back to deterministic legacy tie-breaks.

Calibration JSON is **versioned** and supports both:

- **Global weights** (`tool_stats_global`) learned across the whole suite
- **Per-OWASP weights** (`tool_stats_by_owasp`) learned within each OWASP category slice

When computing `triage_score_v1`, the scorer selects weights using:

- use the case/cluster OWASP slice if it exists **and** its `support.clusters >= min_support_by_owasp`
- else fall back to global weights

The calibration builder keeps outputs deterministic via stable ordering of tools/cases and
deterministic JSON key insertion order. A backwards-compatible alias (`tool_stats`) is also written
for v1 consumers.

---

## Extending the system

### Add a new scanner adapter

1. Add a stable entrypoint: `tools/scan_<tool>.py` (thin argparse wrapper).
2. Implement `tools/<tool>/`:
   - `runner.py` executes the tool and writes raw output
   - `normalize.py` converts raw → `normalized.json` (schema v1.1)
3. Use canonical layout helpers (`sast_benchmark.io.layout.prepare_run_paths(...)`).
4. Register tool in `pipeline/scanners.py` (tool name -> entrypoint + metadata).

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
