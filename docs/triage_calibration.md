# Triage calibration QA runbook

This repo supports a **suite-level triage calibration** workflow.

At a high level:

1. **Per-case analysis** writes per-case artifacts (including `triage_features.csv` and `triage_queue.csv`).
2. A **suite-level builder** aggregates features across cases into `analysis/_tables/triage_dataset.csv`.
3. A **calibration builder** learns per-tool weights from GT and writes `analysis/triage_calibration.json` (plus a CSV report).
4. A **suite eval** summarizes baseline vs calibrated strategies.

Because the calibration JSON is produced at the *suite level*, the calibrated score (`triage_score_v1`) cannot be
applied to per-case `triage_queue.csv` **until after** calibration has been built.
The QA command below performs a second “analysis-only” pass to ensure per-case outputs pick up the calibration.


## CLI helper

The QA helper is implemented as **flags on suite mode**:

- `--qa-calibration` enables the runbook
- `--qa-scope smoke|full` chooses which OWASP slices to run
  - `smoke` → only **A03 + A07**
  - `full` → **A01–A10**
- `--qa-owasp A03,A07` (optional) overrides the scope with an explicit OWASP id list (comma-separated). You can also use a range like `A01-A10`.
- `--qa-no-reanalyze` (optional) skips the second analysis-only pass (not recommended for end-to-end QA).

If you don’t provide suite sources, the command will try these defaults (in order):

1. `examples/suite_inputs/durinn-owasp2021-python-micro-suite_cases.csv`
2. `repos/worktrees/durinn-owasp2021-python-micro-suite`

If neither exists, pass one of: `--suite-file`, `--cases-from`, or `--worktrees-root`.


## Expected artifacts

After the QA command completes, it validates these artifacts exist under `runs/suites/LATEST/...`:

- `analysis/_tables/triage_dataset.csv`
- `analysis/triage_calibration.json`
- `analysis/_tables/triage_calibration_report.csv`
- at least one case `triage_queue.csv` contains a `triage_score_v1` column
- the suite triage eval summary includes the `calibrated` strategy

The filesystem-first validator lives at:

- `pipeline/analysis/qa_calibration_runbook.py`


## Notes for non-scored suites (e.g. Juice Shop)

Suites without ground truth (GT) are **not good calibration candidates**.

Today the QA checklist assumes a “scored” suite where calibration + eval are meaningful.
When extending this QA approach to non-scored suites, we’ll likely want a different checklist,
for example:

- validate per-case analysis artifacts exist
- validate triage queue schema invariants
- skip (or soft-warn) on calibration/eval expectations

This doc is the canonical place to keep those future adjustments.
