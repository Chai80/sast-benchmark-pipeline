# Suite inputs and worktree bootstrapping

This repo supports two related but distinct workflows:

- **Benchmark mode**: run one repo checkout with one or more scanners.
- **Suite mode**: run many *cases* (repos and/or branches) under a single suite id.

The most common confusion is expecting `--mode benchmark --repo-url ...` to also prepare a multi-branch suite. Benchmark mode clones **one checkout**; suite mode expects **many checkouts** (one per case). This doc describes the supported "suite input" paths and the new "repo URL + branches" bridge.

## Decision tree

### 1) I want to scan one repo (single target)

Use **benchmark** (multiple tools) or **scan** (one tool).

- Clone from URL and run multiple tools:

```bash
python sast_cli.py --mode benchmark \
  --repo-url https://github.com/<org>/<repo>.git \
  --scanners semgrep,snyk,sonar \
  --suite-id my_run
```

This clones a single checkout into `repos/<repo_id>/` (deterministic cache) and writes outputs under `runs/suites/<suite_id>/cases/<case_id>/...`.

### 2) I want to scan many cases under one suite id (multi-target)

Use **suite** mode. A *case* is a single repo checkout (often a branch-per-case checkout).

Suite mode supports multiple ways to define cases:

1. **Worktrees root** (recommended for branch-per-case suites)

   You already have a folder containing git worktrees/checkouts (one per case):

   ```bash
   python sast_cli.py --mode suite \
     --worktrees-root repos/worktrees/durinn-owasp2021-python-micro-suite \
     --scanners semgrep,snyk,sonar
   ```

2. **Cases CSV** (portable + CI-friendly)

   Use a CSV with `case_id,repo_path,...`:

   ```bash
   python sast_cli.py --mode suite \
     --cases-from examples/suite_inputs/durinn-owasp2021-python-micro-suite_cases.csv \
     --scanners semgrep,snyk,sonar
   ```

3. **Replay file** (`--suite-file`)

   A Python suite definition saved from a previous run:

   ```bash
   python sast_cli.py --mode suite \
     --suite-file runs/suites/<suite_id>/replay/replay_suite.py \
     --scanners semgrep,snyk,sonar
   ```

4. **Interactive build**

   If you omit suite inputs, the CLI will prompt you to build a suite interactively (not allowed in QA mode).

## Bridge path: repo URL + branches -> worktrees root

For OWASP-style micro-suites (one branch per OWASP category) you typically want:

- one local checkout per branch
- deterministic case ids

Creating those by hand is easy to forget. Suite mode now supports a lightweight bridge:

- Provide `--repo-url` and a branch set via `--branches`
- The CLI bootstraps a deterministic worktrees root:

```
repos/worktrees/<repo_id>/
  _base/        # base clone
  A01/          # worktree for branch A01
  A02/
  ...
```

Example:

```bash
python sast_cli.py --mode suite \
  --repo-url https://github.com/Chai80/durinn-calibration-suite-python.git \
  --branches A01-A10 \
  --scanners semgrep,snyk,sonar
```

Notes:

- `--branches` accepts CSV (e.g. `A03,A07`) and OWASP-ish ranges (e.g. `A01-A10` or `A01..A10`).
- Branch tokens are resolved against remote branches. For example, a token like `A01` can resolve to a
  verbose remote branch name such as `owasp2021-a01-calibration-sample` as long as the match is unique.
  If the match is ambiguous (or missing), pass the exact remote branch names via `--branches`.
- Worktree directory names are sanitized path segments (filesystem-safe).
- The bootstrap is **idempotent**: it reuses `_base` if present, fetches/prunes, and only creates missing worktrees.

## QA calibration workflow

The QA runbook (`--qa-calibration`) is a deterministic two-pass flow:

1. Run the suite (scan + analysis) to build suite-level calibration artifacts.
2. Re-run analysis across all cases so per-case `triage_queue.csv` includes `triage_score_v1`.
3. Validate the expected artifacts exist and print a PASS/FAIL checklist.

With the bridge path, you can run QA on a fresh machine from *only* a repo URL:

Smoke (A03 + A07):

```bash
python sast_cli.py --mode suite \
  --qa-calibration \
  --qa-scope smoke \
  --repo-url https://github.com/Chai80/durinn-calibration-suite-python.git \
  --scanners semgrep,snyk,sonar
```

Full (A01..A10):

```bash
python sast_cli.py --mode suite \
  --qa-calibration \
  --qa-scope full \
  --repo-url https://github.com/Chai80/durinn-calibration-suite-python.git \
  --scanners semgrep,snyk,sonar
```

In QA mode, if you omit `--branches`, the CLI derives branches from the QA scope.
