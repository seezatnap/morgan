use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{ArgAction, ArgGroup, Parser};
use morgan::engine::Engine;
use morgan::julietscript::{
    ScriptSpec, generate_script, lint_script, parse_execution_plan, validate_artifact_name,
};
use morgan::orchestrator::{
    ExecuteScriptOptions, ReplayRunOptions, ReplaySummary, ResumeRunOptions, RunGeneratedOptions,
    replay_run, resume_run, run_generated, run_script,
};
use morgan::preflight::load_input_context;

#[derive(Debug, Parser)]
#[command(
    name = "morgan",
    version,
    about = "JulietScript generation and Juliet run orchestrator"
)]
enum Cli {
    /// Generate a JulietScript file from a master prompt and optional input files.
    ///
    /// This command only writes/validates script output. It does not execute Juliet.
    #[command(
        name = "generate",
        group(
            ArgGroup::new("prompt_source")
                .required(true)
                .args(["master_prompt", "prompt_file"])
        )
    )]
    Generate(GenerateArgs),
    /// Generate JulietScript, run preflight checks, and execute the workflow against Juliet.
    ///
    /// Use this when you want end-to-end orchestration (script generation + execution loop).
    #[command(
        name = "run",
        group(
            ArgGroup::new("prompt_source")
                .required(true)
                .args(["master_prompt", "prompt_file"])
        )
    )]
    Run(RunArgs),
    /// Execute an existing JulietScript file against Juliet without regenerating it.
    #[command(name = "execute")]
    Execute(ExecuteArgs),
    /// Resume an interrupted run from persisted checkpoint state under `.morgan/runs/<run-id>`.
    #[command(name = "resume")]
    Resume(ResumeArgs),
    /// Replay saved Juliet outputs through the classifier and report decision drift.
    #[command(name = "replay")]
    Replay(ReplayArgs),
}

#[derive(Debug, Parser)]
struct GenerateArgs {
    /// Root directory for path resolution and output.
    ///
    /// Relative paths for prompt/input/script/linter manifest are resolved from this directory.
    #[arg(long, default_value = ".")]
    project_root: PathBuf,
    /// Inline master prompt text used to generate the JulietScript.
    ///
    /// Exactly one of `--master-prompt` or `--prompt-file` is required.
    #[arg(long)]
    master_prompt: Option<String>,
    /// File containing the master prompt text.
    ///
    /// Exactly one of `--master-prompt` or `--prompt-file` is required.
    #[arg(long)]
    prompt_file: Option<PathBuf>,
    /// Input context file(s) to embed into the generated create prompt.
    ///
    /// Pass multiple times to include multiple files.
    #[arg(long = "input-file")]
    input_files: Vec<PathBuf>,
    /// Destination path for the generated JulietScript file.
    #[arg(long, default_value = ".morgan/generated.julietscript")]
    script_output: PathBuf,
    /// Artifact identifier used in `create <Artifact> from juliet ...` within the script.
    #[arg(long, default_value = "GeneratedArtifact")]
    artifact_name: String,
    /// Engine value injected into `juliet { engine = ... }` and cadence defaults.
    #[arg(long, value_enum, default_value_t = Engine::Codex)]
    engine: Engine,
    /// Cadence variants count written into the generated script.
    #[arg(long, default_value_t = 2)]
    variants: u32,
    /// Cadence sprint count written into the generated script.
    #[arg(long, default_value_t = 1)]
    sprints: u32,
    /// Cadence survivor cap used in `keep best <N>`.
    #[arg(long, default_value_t = 1)]
    keep_best: u32,
    /// Maximum bytes read per input file when embedding input context.
    ///
    /// Larger files are truncated with a truncation note.
    #[arg(long = "max-input-bytes", default_value_t = 12_000)]
    max_input_bytes: usize,
    /// Path to JulietScript workspace `Cargo.toml` used as lint fallback.
    ///
    /// Morgan tries `julietscript-lint` on PATH first. If not found, it runs
    /// `cargo run --manifest-path <this> -p julietscript-lint ...`.
    #[arg(
        long = "julietscript-manifest",
        default_value = "../julietscript/Cargo.toml"
    )]
    julietscript_manifest: PathBuf,
    /// Skip JulietScript lint validation.
    ///
    /// Use this only for rapid iteration or when linter workspace access is unavailable.
    #[arg(long = "skip-lint", default_value_t = false, action = ArgAction::SetTrue)]
    skip_lint: bool,
}

#[derive(Debug, Parser)]
struct RunArgs {
    /// Root directory for orchestration, git checks, and Juliet execution.
    ///
    /// All relative paths are resolved from this directory.
    #[arg(long, default_value = ".")]
    project_root: PathBuf,
    /// Juliet role name (`juliet --project/--role`) used for state and conversations.
    #[arg(long, default_value = "director-of-engineering")]
    role: String,
    /// Logical project name used for PRD artifact naming and run context.
    #[arg(long, default_value = "morgan-project")]
    project_name: String,
    /// Artifact identifier used in generated JulietScript `create` statement.
    #[arg(long, default_value = "GeneratedArtifact")]
    artifact_name: String,
    /// Inline master prompt text.
    ///
    /// Exactly one of `--master-prompt` or `--prompt-file` is required.
    #[arg(long)]
    master_prompt: Option<String>,
    /// File containing master prompt text.
    ///
    /// Exactly one of `--master-prompt` or `--prompt-file` is required.
    #[arg(long)]
    prompt_file: Option<PathBuf>,
    /// Input file(s) included in the generated script context.
    ///
    /// Pass multiple `--input-file` flags to include multiple files.
    #[arg(long = "input-file")]
    input_files: Vec<PathBuf>,
    /// Destination path for generated JulietScript before execution.
    #[arg(long, default_value = ".morgan/generated.julietscript")]
    script_output: PathBuf,
    /// Engine used for generated script plan and Juliet exec turns.
    #[arg(long, value_enum, default_value_t = Engine::Codex)]
    engine: Engine,
    /// Cadence variants to request during task approval automation.
    #[arg(long, default_value_t = 2)]
    variants: u32,
    /// Cadence sprint count to request during task approval automation.
    #[arg(long, default_value_t = 1)]
    sprints: u32,
    /// Cadence survivor cap (`keep best`) used in script generation.
    #[arg(long, default_value_t = 1)]
    keep_best: u32,
    /// Intended source branch for preflight and branch-repair logic.
    ///
    /// Defaults to the current branch when omitted.
    #[arg(long)]
    source_branch: Option<String>,
    /// Email value to provide automatically if Juliet requests `.swarm-hug/email.txt`.
    #[arg(long)]
    email: Option<String>,
    /// Seconds between automated heartbeat status turns while work is in progress.
    #[arg(long = "heartbeat-seconds", default_value_t = 20)]
    heartbeat_seconds: u64,
    /// Maximum number of non-interactive turns before the run exits.
    #[arg(long = "max-turns", default_value_t = 60)]
    max_turns: u32,
    /// Enable automatic local branch checkout/create when branch mismatch is detected.
    ///
    /// Set to `false` to fail fast instead of modifying local branch state.
    #[arg(long = "auto-fix-branches", default_value_t = true, action = ArgAction::Set)]
    auto_fix_branches: bool,
    /// Ask Juliet to grade result sets with rubric prompts when review/completion signals appear.
    #[arg(long = "auto-grade", default_value_t = true, action = ArgAction::Set)]
    auto_grade: bool,
    /// Explicit path to Juliet binary.
    ///
    /// If omitted, Morgan will try `juliet` on PATH, then `../juliet/target/debug/juliet`,
    /// then `--juliet-manifest`.
    #[arg(long = "juliet-bin")]
    juliet_bin: Option<PathBuf>,
    /// Path to Juliet `Cargo.toml` used as fallback runner when no binary is found.
    #[arg(long = "juliet-manifest", default_value = "../juliet/Cargo.toml")]
    juliet_manifest: PathBuf,
    /// Path to JulietScript workspace `Cargo.toml` used as lint fallback.
    ///
    /// Morgan tries `julietscript-lint` on PATH first, then falls back to this manifest.
    #[arg(
        long = "julietscript-manifest",
        default_value = "../julietscript/Cargo.toml"
    )]
    julietscript_manifest: PathBuf,
    /// Skip JulietScript lint validation before execution.
    #[arg(long = "skip-lint", default_value_t = false, action = ArgAction::SetTrue)]
    skip_lint: bool,
    /// Maximum bytes read from each input file when generating embedded context.
    #[arg(long = "max-input-bytes", default_value_t = 12_000)]
    max_input_bytes: usize,
}

#[derive(Debug, Parser)]
struct ExecuteArgs {
    /// Root directory for orchestration, git checks, and Juliet execution.
    #[arg(long, default_value = ".")]
    project_root: PathBuf,
    /// Juliet role name (`juliet --project/--role`) used for state and conversations.
    #[arg(long, default_value = "director-of-engineering")]
    role: String,
    /// Logical project name used for generated PRD artifact naming.
    #[arg(long, default_value = "morgan-project")]
    project_name: String,
    /// Existing JulietScript file to execute.
    #[arg(long)]
    script_path: PathBuf,
    /// Intended source branch for preflight and branch-repair logic.
    ///
    /// Defaults to the current branch when omitted.
    #[arg(long)]
    source_branch: Option<String>,
    /// Email value to provide automatically if Juliet requests `.swarm-hug/email.txt`.
    #[arg(long)]
    email: Option<String>,
    /// Seconds between automated heartbeat status turns while work is in progress.
    #[arg(long = "heartbeat-seconds", default_value_t = 20)]
    heartbeat_seconds: u64,
    /// Maximum number of non-interactive turns before the run exits.
    #[arg(long = "max-turns", default_value_t = 60)]
    max_turns: u32,
    /// Enable automatic local branch checkout/create when branch mismatch is detected.
    #[arg(long = "auto-fix-branches", default_value_t = true, action = ArgAction::Set)]
    auto_fix_branches: bool,
    /// Ask Juliet to grade result sets with rubric prompts when review/completion signals appear.
    #[arg(long = "auto-grade", default_value_t = true, action = ArgAction::Set)]
    auto_grade: bool,
    /// Explicit path to Juliet binary.
    ///
    /// If omitted, Morgan will try `juliet` on PATH, then `../juliet/target/debug/juliet`,
    /// then `--juliet-manifest`.
    #[arg(long = "juliet-bin")]
    juliet_bin: Option<PathBuf>,
    /// Path to Juliet `Cargo.toml` used as fallback runner when no binary is found.
    #[arg(long = "juliet-manifest", default_value = "../juliet/Cargo.toml")]
    juliet_manifest: PathBuf,
    /// Path to JulietScript workspace `Cargo.toml` used as lint fallback.
    ///
    /// Morgan tries `julietscript-lint` on PATH first, then falls back to this manifest.
    #[arg(
        long = "julietscript-manifest",
        default_value = "../julietscript/Cargo.toml"
    )]
    julietscript_manifest: PathBuf,
    /// Skip JulietScript lint validation before execution.
    #[arg(long = "skip-lint", default_value_t = false, action = ArgAction::SetTrue)]
    skip_lint: bool,
}

#[derive(Debug, Parser)]
struct ResumeArgs {
    /// Root directory containing `.morgan/runs`.
    #[arg(long, default_value = ".")]
    project_root: PathBuf,
    /// Run identifier printed in normal run/execute summaries.
    #[arg(long = "run-id")]
    run_id: String,
}

#[derive(Debug, Parser)]
struct ReplayArgs {
    /// Root directory containing `.morgan/runs`.
    #[arg(long, default_value = ".")]
    project_root: PathBuf,
    /// Run identifier printed in normal run/execute summaries.
    #[arg(long = "run-id")]
    run_id: String,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("morgan: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse() {
        Cli::Generate(args) => run_generate(args),
        Cli::Run(args) => run_full_run(args),
        Cli::Execute(args) => run_execute(args),
        Cli::Resume(args) => run_resume(args),
        Cli::Replay(args) => run_replay(args),
    }
}

fn run_generate(args: GenerateArgs) -> Result<()> {
    let project_root = args
        .project_root
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", args.project_root.display()))?;

    validate_artifact_name(&args.artifact_name)?;

    let prompt = resolve_prompt(args.master_prompt, args.prompt_file, &project_root)?;
    let input_context = load_input_context(&project_root, &args.input_files, args.max_input_bytes)?;
    let script = generate_script(&ScriptSpec {
        artifact_name: args.artifact_name,
        master_prompt: prompt,
        input_context,
        engine: args.engine,
        variants: args.variants,
        sprints: args.sprints,
        keep_best: args.keep_best,
    });

    let script_path = resolve_against(&project_root, &args.script_output);
    write_file(&script_path, &script)?;

    if !args.skip_lint {
        let manifest = resolve_against(&project_root, &args.julietscript_manifest);
        lint_script(&script_path, &manifest)?;
    }

    let plan = parse_execution_plan(&script)?;
    println!(
        "Generated script at {}\nEngine: {}\nVariants: {}\nSprints: {}\nKeep best: {}",
        script_path.display(),
        plan.engine,
        plan.variants,
        plan.sprints,
        plan.keep_best
    );
    Ok(())
}

fn run_full_run(args: RunArgs) -> Result<()> {
    let prompt = resolve_prompt(args.master_prompt, args.prompt_file, &args.project_root)?;

    let summary = run_generated(RunGeneratedOptions {
        project_root: args.project_root,
        role_name: args.role,
        project_name: args.project_name,
        artifact_name: args.artifact_name,
        master_prompt: prompt,
        input_files: args.input_files,
        script_output: args.script_output,
        engine: args.engine,
        variants: args.variants,
        sprints: args.sprints,
        keep_best: args.keep_best,
        source_branch: args.source_branch,
        juliet_bin: args.juliet_bin,
        juliet_manifest: Some(args.juliet_manifest),
        julietscript_manifest: Some(args.julietscript_manifest),
        heartbeat_seconds: args.heartbeat_seconds,
        max_turns: args.max_turns,
        email: args.email,
        auto_fix_branches: args.auto_fix_branches,
        auto_grade: args.auto_grade,
        lint_enabled: !args.skip_lint,
        max_input_bytes: args.max_input_bytes,
    })?;

    print_summary(&summary);
    Ok(())
}

fn run_execute(args: ExecuteArgs) -> Result<()> {
    let summary = run_script(ExecuteScriptOptions {
        project_root: args.project_root,
        role_name: args.role,
        project_name: args.project_name,
        script_path: args.script_path,
        source_branch: args.source_branch,
        juliet_bin: args.juliet_bin,
        juliet_manifest: Some(args.juliet_manifest),
        julietscript_manifest: Some(args.julietscript_manifest),
        heartbeat_seconds: args.heartbeat_seconds,
        max_turns: args.max_turns,
        email: args.email,
        auto_fix_branches: args.auto_fix_branches,
        auto_grade: args.auto_grade,
        lint_enabled: !args.skip_lint,
    })?;

    print_summary(&summary);
    Ok(())
}

fn run_resume(args: ResumeArgs) -> Result<()> {
    let summary = resume_run(ResumeRunOptions {
        project_root: args.project_root,
        run_id: args.run_id,
    })?;
    print_summary(&summary);
    Ok(())
}

fn run_replay(args: ReplayArgs) -> Result<()> {
    let summary = replay_run(ReplayRunOptions {
        project_root: args.project_root,
        run_id: args.run_id,
    })?;
    print_replay_summary(&summary);
    Ok(())
}

fn resolve_prompt(
    inline_prompt: Option<String>,
    prompt_file: Option<PathBuf>,
    project_root: &Path,
) -> Result<String> {
    match (inline_prompt, prompt_file) {
        (Some(inline), None) => Ok(inline),
        (None, Some(path)) => {
            let resolved = resolve_against(project_root, &path);
            fs::read_to_string(&resolved)
                .with_context(|| format!("failed to read prompt file {}", resolved.display()))
        }
        (Some(_), Some(_)) => bail!("provide only one of --master-prompt or --prompt-file"),
        (None, None) => bail!("missing master prompt. Provide --master-prompt or --prompt-file"),
    }
}

fn print_summary(summary: &morgan::orchestrator::RunSummary) {
    println!("Run ID: {}", summary.run_id);
    println!("Script: {}", summary.script_path.display());
    println!("PRD: {}", summary.prd_path.display());
    println!("Completed: {}", summary.completed);
    println!("Artifacts executed: {}", summary.artifact_runs.len());
    for artifact in &summary.artifact_runs {
        let execution_root = artifact
            .execution_root
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "(unknown)".to_string());
        println!(
            "- {} | {} -> {} | completed: {} | root: {} | prd: {}",
            artifact.artifact_name,
            artifact.source_branch,
            artifact.target_branch,
            artifact.completed,
            execution_root,
            artifact.prd_path.display()
        );
    }
    if let Some(resume_id) = &summary.resume_id {
        println!("Resume ID: {resume_id}");
    }
    println!("Turns: {}", summary.turns.len());
    if let Some(last) = summary.turns.last() {
        println!("Last signal: {:?}", last.signal);
        println!("Last response:\n{}", last.received.trim());
    }
}

fn print_replay_summary(summary: &ReplaySummary) {
    println!("Run ID: {}", summary.run_id);
    println!("Turns replayed: {}", summary.total_turns);
    println!("Changed decisions: {}", summary.changed_turns);
    if summary.turns.is_empty() {
        return;
    }

    println!("Per-turn drift:");
    for turn in &summary.turns {
        let changed = if turn.changed { "yes" } else { "no" };
        println!(
            "- {}#{} | original: {:?} | replayed: {:?} | changed: {}",
            turn.artifact_name, turn.turn, turn.original_signal, turn.replayed_signal, changed
        );
    }
}

fn resolve_against(base: &Path, candidate: &Path) -> PathBuf {
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    }
}

fn write_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))
}
