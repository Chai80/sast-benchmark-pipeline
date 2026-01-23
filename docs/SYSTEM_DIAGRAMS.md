# System diagrams

This document is the single place to understand the end-to-end data flow and the internal analysis architecture.

It is intentionally **filesystem-first**: every run produces a stable set of artifacts that can be browsed by a human today and ingested into a DB tomorrow.

---

## System stage dataflow diagram

![System stage dataflow diagram](diagrams/system_stage_dataflow.png)

Notes (refactor-aware):
- Execution engine lives in `pipeline/execution/run_case.py` (coordinator) with helpers in `pipeline/execution/{plan,runner,record}.py`.
- Suite report builder lives in `pipeline/analysis/suite_report/` (legacy wrapper: `pipeline/analysis/suite/suite_report.py`).
- QA calibration runbook lives in `pipeline/analysis/qa_calibration_runbook/` (legacy wrapper: `pipeline/analysis/qa/qa_calibration_runbook.py`).
- Suite CLI runbook lives in `cli/commands/suite/runbook.py` with step modules in `cli/commands/suite/runbook_steps/`.

## End-to-end pipeline

```mermaid
flowchart TD
  %% Inputs: suite mode accepts multiple “work order” sources.
  subgraph Inputs[Suite inputs (work orders)]
    direction TB
    I1[--suite-file<br/>(python replay)]
    I2[--cases-from<br/>(CSV work order)]
    I3[--worktrees-root<br/>(local checkouts)]
    I4[--repo-url + branches<br/>(optional bridge)]
  end

  I4 --> WB[Bootstrap worktrees (optional)<br/>repos/worktrees/<repo_id>/...]
  WB --> I3

  %% Resolver boundary: writes the canonical plan before execution.
  Inputs --> R[Resolver boundary<br/>pipeline/suites/suite_resolver.py]
  R -->|writes plan| S1[suite.json]

  %% Execution: per-case tool runs.
  R --> B[Orchestrator<br/>pipeline/orchestrator.py]

  subgraph SuiteLayout["runs/suites/<suite_id>/"]
    direction TB

    SuiteLayout --> S1[suite.json]
    SuiteLayout --> S2[summary.csv]
    SuiteLayout --> SA[analysis/<br/>_tables/triage_dataset.csv<br/>triage_calibration.json<br/>_tables/triage_calibration_report.csv<br/>_tables/triage_eval_summary.json<br/>qa_calibration_checklist.txt<br/>qa_manifest.json<br/>_tables/gt_tolerance_sweep_report.csv<br/>_tables/gt_tolerance_sweep_tool_stats.csv<br/>gt_tolerance_sweep.json<br/>gt_tolerance_selection.json<br/>_sweeps/gt_tol_<t>/analysis/...]

    subgraph Case["cases/<case_id>/"]
      direction TB
      C1[case.json] --> C2[tool_runs/<tool>/<run_id>/]
      C2 --> C3[run.json]
      C2 --> C4[raw/*]
      C2 --> C5[normalized.json]
      Case --> C6[analysis/*]
      Case --> CG[gt/*]
    end

    SuiteLayout --> R1[replay/replay_suite.py<br/>(optional; interactive replay)]
    SuiteLayout --> R2[replay/replay_command.txt<br/>(optional helper)]
  end

  B -->|execute tools| C2
  C2 -->|normalize| C5
  C5 -->|per-case analysis runner| C6
  C6 -->|export packs| D[benchmark_pack.json<br/>hotspot_drilldown_pack.json]

  %% QA calibration runbook: suite-scoped build + re-analysis.
  C6 -->|--qa-calibration| QA[QA triage calibration runbook]
  QA --> SA
  QA -->|reanalyze cases| C6

  D --> E[(DB Ingestion<br/>future)]
```

Key principles:
- **suite_id** = one benchmark run (experiment instance)
- **case_id** = one target in the suite (repo/branch/commit/worktree)
- **tool + run_id** = one tool execution on one case

---

## Modular analysis architecture

The analysis layer is designed as a stage-based pipeline with two primitives:
- **ctx** (`AnalysisContext`): immutable job packet (paths, IDs, knobs)
- **store** (`ArtifactStore`): in-memory scratchpad shared across stages

```mermaid
flowchart LR
  A[runner.run_suite] --> B[AnalysisContext<br/>ctx]
  A --> C[ArtifactStore<br/>store]

  subgraph Pipelines["Pipelines (ordered stage lists)"]
    P1[benchmark] --> B0[diagnostics_case_context]
    B0 --> B1[overview]
    B1 --> B2[tool_profile]
    B2 --> B3[location_matrix]
    B3 --> B4[pairwise_agreement]
    B4 --> B5[taxonomy]
    B5 --> B6[triage_queue]
    B6 --> B7[consensus_queue]
    B7 --> B8[gt_score]
    B8 --> B9[triage_features]

    P2[reporting] --> R1[benchmark_pack]
    R1 --> R2[hotspot_drilldown_pack]

    P3[diagnostics] --> D0[diagnostics_case_context]
    D0 --> D1[diagnostics_schema]
    D1 --> D2[diagnostics_empty_runs]
  end

  subgraph Registry["Stage Registry"]
    SR[register_stage(name) decorator]
  end

  SR --> B0
  SR --> B1
  SR --> B2
  SR --> B3
  SR --> B4
  SR --> B5
  SR --> B6
  SR --> B7
  SR --> B8
  SR --> B9
  SR --> R1
  SR --> R2
  SR --> D0
  SR --> D1
  SR --> D2

  Pipelines --> O[analysis_manifest.json<br/>+ artifacts]
```

Why this matters:
- Adding a new metric is a **new stage**, not a new ad-hoc script.
- Stages share intermediate results through `store`, avoiding recomputation.
- Benchmark analysis, diagnostics, and reporting are **separate concerns**.

### Suite-scoped analysis (triage calibration)

Triage calibration is suite-scoped and is implemented as a small, filesystem-first pipeline:

`suite_triage_dataset` → `suite_triage_calibration` → `suite_triage_eval`

It writes under `runs/suites/<suite_id>/analysis/` and (when enabled via `--qa-calibration`) triggers
a second analysis-only pass so per-case `triage_queue.csv` can populate `triage_score_v1`.

---

## Compatibility policy

The modular analysis framework is introduced in a **no-break** way:
- existing CLI entrypoints remain stable
- scan output behavior is unchanged
- analysis produces additional artifacts only (e.g., `analysis_manifest.json`, pack JSONs)
