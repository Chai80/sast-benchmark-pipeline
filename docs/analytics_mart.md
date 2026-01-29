# AnalyticsMart (Star Schema)

This project is **filesystem-first**: every suite run writes deterministic artifacts under
`runs/suites/<suite_id>/analysis/`.

That is great for debugging and reproducibility.

For **analytics deliverables** (dashboards, scorecards, and A/B tests), it helps to also have a
small set of **tables with stable join keys**.

The **AnalyticsMart** export does that.

## Where it writes

Each time a suite-level triage eval is built, we also export:

`runs/suites/<suite_id>/AnalyticsMart/`

Inside that folder:

- `dim_suite_run.csv`
- `dim_case.csv`
- `dim_tool_run.csv`
- `fact_eval_case_k.csv`
- `fact_eval_suite_k.csv`
- `fact_tool_value.csv`
- `analytics_mart_manifest.json`
- `README.md`

## How to generate

### Automatic

The suite runbook step that builds `triage_eval` also triggers AnalyticsMart export (best-effort).

### Manual

You can also run it directly:

```bash
python -m pipeline.analysis.analytics_mart \
  --suite-dir runs/suites/<suite_id>
```

## What “star schema” means here

Plain-English definition:

- **Dimensions** are “lookup tables” you join in to slice/filter results.
  - Example: case → OWASP category; tool_run → tool version.
- **Facts** are “measurement tables” (metrics you aggregate).
  - Example: precision@25 for a case under a given strategy.

The benefit is that dashboards and experiments become a few simple SQL joins instead of a pile of
custom parsing code.

## Table definitions

### `dim_suite_run`

**Grain:** one row per suite run.

**Primary key:** `suite_run_id`

**What it’s for:** identify the experiment/run and capture signatures so you can compare runs.

Common columns:

- `suite_run_id`: the suite folder name (and `suite.json.suite_run_id`)
- `benchmark_id`: stable workload id (from `suite.json.plan.workload_id` when present)
- `pipeline_git_commit`: pipeline code version
- `toolset_signature`: hash of scanner config receipts across the suite
- `calibration_id`: hash of `analysis/triage_calibration.json` (empty if none)

### `dim_case`

**Grain:** one row per case (target) in the benchmark.

**Primary key:** `(benchmark_id, case_id)`

**Important note:** `case_id` here is the **suite layout folder name** under `runs/suites/<suite_id>/cases/`.
(This matches the IDs used by the analysis artifacts.)

**What it’s for:** slice results by OWASP category, track, etc.

Common columns:

- `owasp_id`: inferred OWASP code (A01–A10) from case naming/tags
- `gt_total`: GT total for the case (from triage eval when available, else `gt/gt_score.json`)
- `expected_branch` / `expected_commit`: if set in case manifest

### `dim_tool_run`

**Grain:** one row per tool execution (per case).

**Primary key:** `(suite_run_id, case_id, tool, run_id)`

**What it’s for:** provenance + performance (tool versions, runtime) and debugging.

This is built from `cases/<case_id>/tool_runs/**/run.json` + `metadata.json` + `config_receipt.json`.

### `fact_eval_case_k`

**Grain:** one row per *(suite run, case, strategy, k)*.

**Primary key:** `(suite_run_id, case_id, strategy, k)`

**What it’s for:** this is your **paired unit** for A/B testing strategies.

Common measures:

- `precision_at_k`
- `coverage_at_k`
- `tp_at_k`, `denom_at_k`

Source: `analysis/_tables/triage_eval_by_case.csv`

### `fact_eval_suite_k`

**Grain:** one row per *(suite run, strategy, k, agg_type)*.

**Primary key:** `(suite_run_id, strategy, k, agg_type)` where `agg_type ∈ {macro, micro}`

**What it’s for:** headline KPIs for dashboards.

Source: `analysis/_tables/triage_eval_summary.json`

### `fact_tool_value`

**Grain:** long-form metrics per tool.

**Primary key:** `(suite_run_id, tool, metric_name)`

**What it’s for:** tool contribution / “signal” analysis.

Two types of rows:

- `metric_group = utility`: from `triage_tool_utility.csv`
- `metric_group = marginal`: from `triage_tool_marginal.csv` (if present)

Examples of `metric_name`:

- `utility.unique_gt_ids`
- `utility.exclusive_neg_clusters`
- `marginal.baseline.k25.delta_precision`
- `marginal.agreement.k25.delta_gt_coverage`

## How this supports A/B testing

### Strategy A/B (same tool outputs, different ranking logic)

Treat each `case_id` as a paired unit.

Example query idea (pseudo-SQL):

```sql
-- ΔCoverage@25 per case, calibrated vs baseline
SELECT
  case_id,
  MAX(CASE WHEN strategy = 'calibrated' THEN coverage_at_k END)
    - MAX(CASE WHEN strategy = 'baseline' THEN coverage_at_k END) AS delta_coverage
FROM fact_eval_case_k
WHERE suite_run_id = '<suite_id>' AND k = 25
GROUP BY case_id;
```

### Tool/version A/B (different tool outputs)

Compare two different `suite_run_id` values for the same benchmark.

```sql
-- micro precision@k across two runs
SELECT
  k,
  MAX(CASE WHEN suite_run_id = 'run_old' THEN precision_at_k END) AS precision_old,
  MAX(CASE WHEN suite_run_id = 'run_new' THEN precision_at_k END) AS precision_new
FROM fact_eval_suite_k
WHERE strategy = 'baseline' AND agg_type = 'micro'
GROUP BY k
ORDER BY k;
```

## Implementation

The exporter lives in:

- `pipeline/analysis/analytics_mart/`

And is invoked best-effort from:

- `pipeline/analysis/suite/triage_eval/io.py`

So it should never break the runbook if something is missing.
