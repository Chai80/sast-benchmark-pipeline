# experiments/

This folder contains **prototype / exploratory code** that is not wired into the main CLI pipeline.

We keep these here (instead of under `pipeline/` or top-level packages like `api/`) to:

- avoid accidental imports and “spaghetti” coupling,
- keep dependency boundaries clear (pipeline orchestrates; tools execute; contracts stay lowest),
- make it obvious what code is stable vs. experimental.

## Contents

- `api_prototype/` — in-memory models + a small ingest helper (no DB). Not used by the CLI.
- `gt_scoring/` — legacy/prototype GT scoring helpers. Not currently invoked by the analysis runner.

If/when these become real product surfaces, we should move them into the appropriate package with tests and docs.
