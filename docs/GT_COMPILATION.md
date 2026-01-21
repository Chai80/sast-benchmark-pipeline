# GT catalog compilation and normalization

Durinn supports **multiple ground-truth (GT) authoring styles** across suites:

- **YAML catalog**: `benchmark/gt_catalog.yaml`
- **In-code markers**:
  - `# DURINN_GT id=... track=... set=... (optional owasp=...)`
  - `# GT:<ID>_START` / `# GT:<ID>_END`

This flexibility is great for suite authors, but it can easily create "spaghetti"
in the pipeline if every stage implements its own GT discovery/parsing rules.

## The architecture rule

**All downstream analysis consumes a single canonical artifact in the suite layout:**

`runs/suites/<suite_id>/cases/<case_id>/gt/gt_catalog.yaml`

Suite execution is responsible for materializing it.

## How it works

During suite case preparation:

1. If the repo contains `benchmark/gt_catalog.yaml`, the pipeline **copies it verbatim**
   into the case folder (`<case_dir>/gt/gt_catalog.yaml`).
2. Otherwise, the pipeline **extracts GT from in-repo markers** and writes a
   minimal `gt_catalog.yaml` (and an optional JSON twin for debugging).

This is implemented in:

- `sast_benchmark.gt.catalog.materialize_case_gt_catalog` (core; no higher-level imports)
- invoked from `pipeline.execution.run_case._capture_optional_benchmark_yaml`

## Why this keeps dependencies one-directional

This establishes a clean flow:

`suite repo (any GT authoring style) -> suite artifacts (canonical gt_catalog.yaml) -> analysis`

Execution/orchestration produces artifacts; analysis reads artifacts. Analysis does
not need to re-open the repo or re-implement GT parsing logic.

## What is "normalized" here?

"Normalized" means **the pipeline always produces the same output contract**
(`gt/gt_catalog.yaml`) for any supported suite GT authoring style.

Suites may still include additional metadata fields in their items; the scorer
uses a stable subset (`id`, `file`, `start_line`, `end_line`, `track`, `set`).
