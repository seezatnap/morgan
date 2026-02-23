# Execution Model

This document describes the current `run` / `execute` orchestration flow, including persisted run memory used by `resume` and `replay`.

## 0. Process Model

- `run`, `execute`, and `resume` are launched as detached background workers.
- Foreground CLI invocation prints manager metadata (manager id, pid, logfile path) and exits.
- Worker logs are written to `.morgan/logs/<manager-id>.log`.
- Worker registry records are stored in `.morgan/manager/processes/<manager-id>.json`.
- `morgan-manager` provides status/kill/logs/cleanup operations over those worker records.

## 1. Script Plan Discovery

Morgan parses the JulietScript and builds an ordered list of artifact plans from `create` statements.

Per artifact plan:

- artifact name
- `using [...]` dependencies
- optional target branch override from `with { ... }` via:
  - `target_branch = "<branch>";`, or
  - `// morgan.target-branch = <branch>;`
- cadence values (`engine`, `variants`, `sprints`, `keep best`)
- create prompt body

Dependency validation enforces order-by-appearance:

- if artifact `B` depends on `A`, then `A` must appear earlier in the script.
- duplicate artifact names are rejected.

## 2. Preflight

Morgan validates:

- project root exists
- repository is a git worktree
- HEAD is on a named branch (not detached)
- input files exist/readable (`run` generation path)
- lint availability:
  - `julietscript-lint` on `PATH`, or
  - manifest fallback exists

## 3. Codex Readiness

Before orchestration starts (and before replay), Morgan checks Codex availability:

- runs `codex login status`
- logs a warning if readiness fails, then continues with heuristic classifier fallback

## 4. Juliet Runner Resolution

Morgan resolves Juliet in this order:

1. `--juliet-bin`
2. `juliet` on `PATH`
3. sibling debug binary `../juliet/target/debug/juliet`
4. `--juliet-manifest` Cargo fallback

Then it initializes role state with:

- `juliet init --project <role>`

## 5. Branch Model

Initial source branch:

- `--source-branch`, otherwise current branch.

For each artifact in order:

1. target branch is resolved by:
   - explicit artifact override when provided, otherwise
   - derived `feature/<artifact-slug>` (with numeric suffix on collision)
2. artifact runs with that `(source, target)` pair
3. next artifact source branch becomes previous artifact target branch

This creates a dependency chain such as:

- `main -> feature/artifact-a -> feature/artifact-b`

## 6. Per-Artifact Loop

For each artifact:

1. Morgan writes an artifact-scoped PRD under:
   - `.juliet/<role>/artifacts/<project>-<artifact>-morgan-prd.md`
2. Morgan starts Juliet with source/target/dependency context in the kickoff message.
3. Each turn uses `juliet exec --json`, preserving `resume_id`.
4. Morgan runs hybrid turn classification:
   - Codex classification from Juliet output only:
     - `codex exec "<classifier prompt>" --json --skip-git-repo-check`
   - deterministic guardrail overrides for:
     - email value requests (`.swarm-hug/email.txt`)
     - task review prompts
     - branch clarification / branch mismatch prompts
   - heuristic fallback classification when Codex classification fails
5. Final signal determines next message:
   - `needs_email`
   - `needs_task_review`
   - `still_working`
   - `results_review`
   - `results_complete`
   - `branch_clarification`
   - `idle`
   - `unknown`
6. Every outbound message includes execution context:
   - artifact
   - source branch
   - destination/target branch
   - dependencies

## 7. Lint Model

When linting is enabled:

1. try `julietscript-lint` on `PATH`
2. fallback to `cargo run --manifest-path <manifest> -p julietscript-lint -- ...`

## 8. Completion + Summary

Morgan returns:

- run id
- overall completion flag
- final resume id
- all turn records
- per-artifact summaries:
  - artifact
  - dependencies
  - source/target branches
  - per-artifact PRD path
  - completion status

For detached worker runs, this summary is written to the worker logfile.

## 9. Run Memory (Event-Sourced Checkpoints)

For every `run` / `execute`, Morgan creates:

- `.morgan/runs/<run-id>/state.json` (typed checkpoint snapshot)
- `.morgan/runs/<run-id>/events.jsonl` (append-only event stream)

Checkpoint updates happen:

1. At run start/resume.
2. When an artifact begins.
3. After every turn (instruction state, `resume_id`, signal, and turn history).
4. When an artifact completes.
5. When run status transitions to completed/failed.

Turn records include both raw and final signals plus decision metadata (source/rule/error) for auditability.

The checkpoint contains enough information to resume mid-artifact deterministically.

## 10. Resume + Replay

- `resume` loads `state.json`, restores active artifact state (`next_instruction`, turn history, `resume_id`, branch context), and continues from the next unresolved turn.
- `replay` reads stored turn outputs and re-runs hybrid classification per turn to report decision drift (`original_signal` vs `replayed_signal`).
