# System diagrams

This document is the single place to understand the end-to-end data flow and the internal analysis architecture.

It is intentionally **filesystem-first**: every run produces a stable set of artifacts that can be browsed by a human today and ingested into a DB tomorrow.

---

## End-to-end pipeline

```mermaid
flowchart TD
  A[Suite Plan<br/>optional YAML] -->|cases + tools| B[Orchestrator<br/>pipeline/orchestrator.py]

  subgraph SuiteLayout["runs/suites/<suite_id>/"]
    direction TB

    subgraph Case["cases/<case_id>/"]
      direction TB
      C1[case.json] --> C2[tool_runs/<tool>/<run_id>/]
      C2 --> C3[run.json]
      C2 --> C4[raw/*]
      C2 --> C5[normalized.json]
      Case --> C6[analysis/*]
    end

    SuiteLayout --> S1[suite.json]
    SuiteLayout --> S2[summary.md]
  end

  B -->|execute tools| C2
  C2 -->|normalize| C5
  C5 -->|analysis runner| C6
  C6 -->|export packs| D[benchmark_pack.json<br/>hotspot_drilldown_pack.json]
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
    P1[benchmark] --> S1[overview]
    S1 --> S2[tool_profile]
    S2 --> S3[location_matrix]
    S3 --> S4[pairwise_agreement]
    S4 --> S5[taxonomy]
    S5 --> S6[triage_queue]
    P2[reporting] --> R1[benchmark_pack]
    R1 --> R2[hotspot_drilldown_pack]
    P3[diagnostics] --> D1[diagnostics_schema]
    D1 --> D2[diagnostics_empty_runs]
  end

  subgraph Registry["Stage Registry"]
    SR[register_stage(name) decorator]
  end

  SR --> S1
  SR --> S2
  SR --> S3
  SR --> S4
  SR --> S5
  SR --> S6
  SR --> R1
  SR --> R2
  SR --> D1
  SR --> D2

  Pipelines --> O[analysis_manifest.json<br/>+ artifacts]
```

Why this matters:
- Adding a new metric is a **new stage**, not a new ad-hoc script.
- Stages share intermediate results through `store`, avoiding recomputation.
- Benchmark analysis, diagnostics, and reporting are **separate concerns**.

---

## Compatibility policy

The modular analysis framework is introduced in a **no-break** way:
- existing CLI entrypoints remain stable
- scan output behavior is unchanged
- analysis produces additional artifacts only (e.g., `analysis_manifest.json`, pack JSONs)
