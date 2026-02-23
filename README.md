# Morgan

Morgan is a Rust CLI/library for orchestrating Juliet workflows from JulietScript.

It supports:

1. Generating JulietScript from a master prompt and input files.
2. Linting JulietScript (`julietscript-lint` on `PATH` first, manifest fallback second).
3. Executing JulietScript against Juliet in non-interactive heartbeat loops.
4. Running ordered multi-artifact plans from one script (`create A`, then `create B using [A]`, etc.).
5. Classifying Juliet output with a hybrid decision engine (Codex + deterministic guardrails + heuristic fallback).
6. Persisting per-turn run state/events for deterministic resume and replay analysis.

## Requirements

- Rust/Cargo (for building and running Morgan).
- Juliet available by one of:
  - `juliet` on `PATH`
  - `--juliet-bin <path>`
  - `--juliet-manifest <path to Cargo.toml>`
- Codex CLI installed and authenticated is recommended for highest-quality classification.
  - If readiness checks fail, Morgan logs a warning and falls back to deterministic heuristics.
- JulietScript lint available by one of:
  - `julietscript-lint` on `PATH`
  - `--julietscript-manifest <path to julietscript workspace Cargo.toml>`
- A git repository for `run` / `execute`.

## Build

```bash
cd .
cargo build
```

## Commands

```bash
cargo run -- --help
cargo run --bin morgan-manager -- --help
```

- `generate`: create a JulietScript file only.
- `run`: generate script + execute orchestrated workflow in a background worker.
- `execute`: execute an existing JulietScript file in a background worker.
- `resume`: continue an interrupted run from `.morgan/runs/<run-id>/state.json` in a background worker.
- `replay`: reclassify saved Juliet outputs and report signal drift.
- `morgan-manager`:
  - `status` table of running workers (default command)
  - `kill --id <manager-id|run-id>` to stop a worker
  - `logs --id <manager-id|run-id>` to print its logfile path
  - `cleanup` to remove stale manager records

## Background Execution

`run`, `execute`, and `resume` always spawn a detached worker process.

The foreground command prints:

- manager id (`mgr-...`)
- worker pid
- logfile path

Logfiles are written under:

- `.morgan/logs/<manager-id>.log`

Manager records are written under:

- `.morgan/manager/processes/<manager-id>.json`

## Quick Start

### Generate Script Only

```bash
cargo run -- generate \
  --project-root ../juliet \
  --master-prompt "Build a robust orchestration CLI." \
  --input-file ../juliet/prds/init.md \
  --artifact-name OrchestratorArtifact \
  --script-output ../juliet/.morgan/orchestrator.julietscript
```

### Generate + Execute

```bash
cargo run -- run \
  --project-root ../juliet \
  --role director-of-engineering \
  --project-name orchestrator \
  --master-prompt "Build and validate the orchestration CLI." \
  --input-file ../juliet/prds/init.md \
  --engine codex \
  --variants 3 \
  --sprints 2 \
  --source-branch main \
  --email you@example.com
```

Inspect active workers:

```bash
cargo run --bin morgan-manager -- --project-root ../juliet status
```

Stop a worker:

```bash
cargo run --bin morgan-manager -- --project-root ../juliet kill --id mgr-1739971812345-12345
```

### Execute Existing Script

```bash
cargo run -- execute \
  --project-root ../juliet \
  --role director-of-engineering \
  --project-name orchestrator \
  --script-path examples/dependent-artifacts.julietscript \
  --source-branch main \
  --email you@example.com
```

### Execute Without Lint

```bash
cargo run -- execute \
  --project-root ../juliet \
  --role director-of-engineering \
  --project-name orchestrator \
  --script-path examples/dependent-artifacts.julietscript \
  --skip-lint \
  --email you@example.com
```

### Resume Interrupted Run

```bash
cargo run -- resume \
  --project-root ../juliet \
  --run-id run-1739971812345-12345
```

### Replay Classifier Decisions

```bash
cargo run -- replay \
  --project-root ../juliet \
  --run-id run-1739971812345-12345
```

## Ordered Multi-Artifact Behavior

`execute` and `run` parse all `create` statements in appearance order.

Example script:

- `examples/dependent-artifacts.julietscript`

Execution semantics:

1. Artifact dependencies must reference artifacts declared earlier (`using [ArtifactA]` before `ArtifactB` execution).
2. Each artifact is executed serially.
3. Branch chain is propagated automatically:
   - initial source branch from `--source-branch` (or current branch)
   - artifact target branch defaults to `feature/<artifact-slug>`
   - next artifact source branch becomes previous artifact target branch
4. Every Juliet turn includes explicit branch context:
   - source branch
   - destination/target branch
   - artifact name
   - dependency list

## Runtime Action Selection

After every Juliet response, Morgan uses a hybrid decision path:

1. Ask Codex for an action label from Juliet output.
2. Apply deterministic guardrails for high-risk prompts (email request, task review request, branch clarification).
3. Fall back to heuristic classification if Codex classification fails.

Codex invocation:

```bash
codex exec "<classifier prompt containing Juliet output>" --json --skip-git-repo-check
```

Allowed actions:

- `needs_email`
- `needs_task_review`
- `still_working`
- `results_review`
- `results_complete`
- `branch_clarification`
- `idle`
- `unknown`

Morgan stores both raw and final per-turn signals in run memory. The final signal drives next-turn behavior (email reply, task approval, status polling, grading prompts, branch repair prompts, etc.).

## Run Memory + Replay

For `run` and `execute`, Morgan writes run artifacts to:

- `.morgan/runs/<run-id>/state.json`
- `.morgan/runs/<run-id>/events.jsonl`

`state.json` includes execution checkpoint fields (`next_artifact_index`, `active_artifact`, `shared_resume_id`, prior turn history, completed artifact summaries, and per-turn decision traces like raw signal/source/rule). This supports:

1. Crash/interruption resume with `morgan resume --run-id <id>`
2. Deterministic replay classification with `morgan replay --run-id <id>`

## Lint Resolution

When linting is enabled, Morgan resolves lint execution in this order:

1. `julietscript-lint` on `PATH`
2. `cargo run --manifest-path <julietscript-manifest> -p julietscript-lint -- ...`

Defaults:

- `--juliet-manifest ../juliet/Cargo.toml`
- `--julietscript-manifest ../julietscript/Cargo.toml`

## Output Summary

`run`, `execute`, and `resume` write summary output into their worker logfile:

- run id
- script path
- final PRD path
- overall completion
- artifact count
- per-artifact lines: `artifact | source -> target | completed | prd`
- final resume id
- total turns
- last signal and response text

## Detailed Docs

- `docs/EXECUTION_MODEL.md`
- `docs/CLI_REFERENCE.md`

## Library Entry Points

- `morgan::orchestrator::run_generated`
- `morgan::orchestrator::run_script`
- `morgan::orchestrator::resume_run`
- `morgan::orchestrator::replay_run`
