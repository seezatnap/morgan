# CLI Reference

Use:

```bash
cargo run -- --help
cargo run -- generate --help
cargo run -- run --help
cargo run -- execute --help
cargo run -- resume --help
cargo run -- replay --help
```

## `generate`

Purpose:

- generate and optionally lint a JulietScript file.

Required:

- exactly one of:
  - `--master-prompt <text>`
  - `--prompt-file <path>`

Key options:

- `--project-root <dir>` path base for relative args.
- `--input-file <path>` repeatable input context files.
- `--script-output <path>` generated script path.
- `--artifact-name <name>` create artifact identifier.
- `--engine <codex|claude>` script engine field.
- `--variants <n>` cadence variants.
- `--sprints <n>` cadence sprints.
- `--keep-best <n>` cadence survivor cap.
- `--max-input-bytes <n>` per-file truncation cap.
- `--julietscript-manifest <path>` lint fallback manifest.
- `--skip-lint` disable lint.

## `run`

Purpose:

- generate script, lint, and execute orchestration against Juliet.

Required:

- exactly one of:
  - `--master-prompt <text>`
  - `--prompt-file <path>`

Key options:

- all relevant `generate` options.
- `--role <name>` Juliet role.
- `--project-name <name>` PRD naming prefix.
- `--source-branch <branch>` initial source branch.
- `--email <email>` value used for `.swarm-hug/email.txt` requests.
- `--heartbeat-seconds <n>` polling cadence.
- `--max-turns <n>` loop cap.
- `--auto-fix-branches <true|false>` branch repair behavior.
- `--auto-grade <true|false>` grading prompts behavior.
- `--juliet-bin <path>` explicit Juliet binary.
- `--juliet-manifest <path>` Juliet fallback manifest.

## `execute`

Purpose:

- execute an existing JulietScript file with ordered multi-artifact orchestration.

Required:

- `--script-path <path>`

Key options:

- `--project-root <dir>`
- `--role <name>`
- `--project-name <name>`
- `--source-branch <branch>`
- `--email <email>`
- `--heartbeat-seconds <n>`
- `--max-turns <n>`
- `--auto-fix-branches <true|false>`
- `--auto-grade <true|false>`
- `--juliet-bin <path>`
- `--juliet-manifest <path>`
- `--julietscript-manifest <path>`
- `--skip-lint`

## `resume`

Purpose:

- resume an interrupted/partial run from persisted checkpoint state.

Required:

- `--run-id <id>`

Key options:

- `--project-root <dir>` base containing `.morgan/runs`.

## `replay`

Purpose:

- replay saved Juliet output through hybrid classification (Codex + guardrails + fallback) and report drift from original actions.

Required:

- `--run-id <id>`

Key options:

- `--project-root <dir>` base containing `.morgan/runs`.

## Runtime Requirements

- Codex CLI installed and logged in is recommended for best classifier quality.
  - If `codex login status` readiness checks fail, Morgan warns and uses heuristic fallback.
- Juliet available through binary or manifest fallback.
- Git repository with named current branch.
- JulietScript lint available on `PATH` or via manifest fallback (unless `--skip-lint`).

## Examples

Single-artifact run:

```bash
cargo run -- run \
  --project-root ../juliet \
  --role director-of-engineering \
  --project-name orchestrator \
  --master-prompt "Build and validate the orchestration CLI." \
  --input-file ../juliet/prds/init.md \
  --source-branch main \
  --email you@example.com
```

Multi-artifact execute:

```bash
cargo run -- execute \
  --project-root ../juliet \
  --role director-of-engineering \
  --project-name orchestrator \
  --script-path examples/dependent-artifacts.julietscript \
  --source-branch main \
  --email you@example.com
```

Resume:

```bash
cargo run -- resume \
  --project-root ../juliet \
  --run-id run-1739971812345-12345
```

Replay:

```bash
cargo run -- replay \
  --project-root ../juliet \
  --run-id run-1739971812345-12345
```
