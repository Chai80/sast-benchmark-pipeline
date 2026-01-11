# Durinn — SAST Benchmark & Normalization Pipeline

One-liner: Run multiple SAST/security scanners against one or many repos, produce comparable outputs,
and compute cross-tool analysis (agreement/hotspots/taxonomy/triage + optional GT scoring).

## TL;DR
- Produces: Bronze (raw), Silver (normalized schema v1.1), Gold (analysis artifacts)
- Primary unit: suite → cases → tool runs
- Start here: run a scan/benchmark/suite in <5 minutes (see Quickstart)

## Documentation
- ARCHITECTURE.md (system overview + contracts)
- normalized-schema.md (normalized.json contract)
- (optional) docs/… for analysis artifacts definitions

## Quickstart (5 minutes)
### 1) Install + venv
### 2) Configure env vars (.env)
### 3) Run one tool (scan mode)
### 4) Run multiple tools (benchmark mode)
### 5) Run a multi-case suite (suite mode, CSV/worktrees)
> Link to “Advanced suite definitions” below.

## Key concepts
### Bronze / Silver / Gold
### Suite / Case / Tool run
### repos/ is an input cache (safe to delete)
### runs/ is output (do not commit)

## Requirements
- Python 3.10+
- git
- Scanner prerequisites (table):
  - Semgrep
  - Snyk (token)
  - SonarCloud / sonar-scanner (token/org)
  - Aikido (client id/secret)

## CLI overview
- `--mode` values: scan | benchmark | suite | analyze | export
- Common flags:
  - `--repo-key` / `--repo-url`
  - `--scanners` / `--scanner`
  - `--suite-id`
  - `--cases-from` / `--worktrees-root` / `--suite-file`
  - `--no-suite` (legacy)
- “Show me help” examples:
  - `python sast_cli.py --help`
  - `python sast_cli.py --mode suite --help`

## Outputs (where to look)
### Suite layout (preferred)
- First file to open: `runs/suites/<suite_id>/summary.csv`
- Traceability:
  - `case.json` (ground truth)
  - `tool_runs/<tool>/<run_id>/run.json` + `metadata.json`
  - `raw.*` + `normalized.json`
### Legacy layout (when --no-suite)
- Brief explanation + one small tree
> Link to ARCHITECTURE.md for full trees.

## Debugging & troubleshooting
- “A scan failed” checklist
- “Normalized.json missing” checklist
- Common gotchas (shell comments, compileall, PATH/tool installs)

## Advanced usage
### Suite from worktrees
- `scripts/make_worktrees.sh` flow
### Python suite definitions (`--suite-file`)
- Minimal example + link to a real example file
### Export mode (JSONL / warehouse ingestion)
- What it’s for
- How to run it
- Where outputs go

## Extending the repo (for contributors)
### Add a new scanner
- Create `tools/scan_<tool>.py` entrypoint
- Implement `tools/<tool>/runner.py` + `normalize.py`
- Register in `pipeline/scanners.py`
- Required artifacts: raw + normalized + metadata + run.json
### Add a new analysis metric
- Add stage under `pipeline/analysis/stages/`
- Register stage + update pipeline list

## Development
- Running tests
- Lint/format commands (if any)
- Repo hygiene: don’t commit `repos/`, `runs/`, `.env`
- Contributing guidelines / PR expectations

## License / Security notes
- Token handling
- Don’t upload raw outputs if they contain sensitive code paths, etc.
