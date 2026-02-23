use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use clap::{ArgAction, ArgGroup, Parser};
use morgan::engine::Engine;
use morgan::julietscript::{
    ScriptArtifactSpec, ScriptSpec, generate_script, lint_script, parse_execution_plans,
    validate_artifact_name, validate_target_branch,
};
use morgan::orchestrator::{
    ExecuteScriptOptions, ReplayRunOptions, ReplaySummary, ResumeRunOptions, replay_run,
    resume_run, run_script,
};
use morgan::process_manager::{
    ENV_FOREGROUND_WORKER, ENV_MANAGER_ID, ENV_MANAGER_LOG_PATH, ENV_MANAGER_RECORD_PATH,
    ManagedProcessRecord, ManagedProcessStatus, ensure_manager_dirs, generate_manager_id,
    is_foreground_worker, load_record, logs_dir, mark_current_process_exited,
    mark_current_process_run_id, mark_current_process_running, record_path as manager_record_path,
    write_record,
};
use morgan::run_memory::now_unix_ms;
use serde::{Deserialize, Serialize};

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
    /// This command starts a detached background worker and returns manager/log metadata.
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
    ///
    /// This command starts a detached background worker and returns manager/log metadata.
    #[command(name = "execute")]
    Execute(ExecuteArgs),
    /// Resume an interrupted run from persisted checkpoint state under `.morgan/runs/<run-id>`.
    ///
    /// This command starts a detached background worker and returns manager/log metadata.
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
    ///
    /// Ignored when `--artifact-plan-file` is supplied.
    #[arg(long)]
    artifact_name: Option<String>,
    /// JSON file describing multiple artifacts for script generation.
    ///
    /// When set, this overrides `--artifact-name` and enables multi-artifact generation.
    #[arg(long = "artifact-plan-file")]
    artifact_plan_file: Option<PathBuf>,
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
    ///
    /// Ignored when `--artifact-plan-file` is supplied.
    #[arg(long)]
    artifact_name: Option<String>,
    /// JSON file describing multiple artifacts for script generation.
    ///
    /// When set, this overrides `--artifact-name` and enables multi-artifact generation.
    #[arg(long = "artifact-plan-file")]
    artifact_plan_file: Option<PathBuf>,
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

const DEFAULT_ARTIFACT_NAME: &str = "GeneratedArtifact";

#[derive(Debug, Deserialize)]
struct ArtifactPlanFile {
    artifacts: Vec<ArtifactPlanEntry>,
}

#[derive(Debug, Deserialize)]
struct ArtifactPlanEntry {
    name: String,
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    input_files: Vec<PathBuf>,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default)]
    using: Vec<String>,
    #[serde(default)]
    target_branch: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TargetBranchSidecar {
    #[serde(default)]
    target_branches: BTreeMap<String, String>,
}

fn main() {
    let result = run();
    let exit_code = if result.is_ok() { 0 } else { 1 };
    let _ = mark_current_process_exited(exit_code);

    if let Err(err) = result {
        eprintln!("morgan: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    if should_run_in_background(&cli) && !is_foreground_worker() {
        return spawn_background_worker(&cli);
    }
    if is_foreground_worker() {
        let _ = mark_current_process_running();
    }

    match cli {
        Cli::Generate(args) => run_generate(args),
        Cli::Run(args) => run_full_run(args),
        Cli::Execute(args) => run_execute(args),
        Cli::Resume(args) => run_resume(args),
        Cli::Replay(args) => run_replay(args),
    }
}

fn should_run_in_background(cli: &Cli) -> bool {
    matches!(cli, Cli::Run(_) | Cli::Execute(_) | Cli::Resume(_))
}

fn managed_command_name(cli: &Cli) -> &'static str {
    match cli {
        Cli::Run(_) => "run",
        Cli::Execute(_) => "execute",
        Cli::Resume(_) => "resume",
        Cli::Generate(_) => "generate",
        Cli::Replay(_) => "replay",
    }
}

fn managed_project_root(cli: &Cli) -> PathBuf {
    match cli {
        Cli::Run(args) => args.project_root.clone(),
        Cli::Execute(args) => args.project_root.clone(),
        Cli::Resume(args) => args.project_root.clone(),
        Cli::Generate(args) => args.project_root.clone(),
        Cli::Replay(args) => args.project_root.clone(),
    }
}

fn spawn_background_worker(cli: &Cli) -> Result<()> {
    let raw_project_root = managed_project_root(cli);
    let project_root = raw_project_root
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", raw_project_root.display()))?;
    ensure_manager_dirs(&project_root)?;

    let manager_id = generate_manager_id();
    let log_path = logs_dir(&project_root).join(format!("{manager_id}.log"));
    let record_path = manager_record_path(&project_root, &manager_id);
    let command = managed_command_name(cli).to_string();
    let now = now_unix_ms();

    let record = ManagedProcessRecord {
        id: manager_id.clone(),
        pid: 0,
        command,
        project_root: project_root.clone(),
        log_path: log_path.clone(),
        run_id: None,
        status: ManagedProcessStatus::Launching,
        exit_code: None,
        started_at_unix_ms: now,
        updated_at_unix_ms: now,
    };
    write_record(&record_path, &record)?;

    let stdout_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("failed to open {}", log_path.display()))?;
    let stderr_log = stdout_log
        .try_clone()
        .with_context(|| format!("failed to clone {}", log_path.display()))?;

    let exe = env::current_exe().context("failed to resolve current executable path")?;
    let args = env::args_os().skip(1).collect::<Vec<OsString>>();
    let mut child = Command::new(exe);
    child
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log))
        .env(ENV_FOREGROUND_WORKER, "1")
        .env(ENV_MANAGER_ID, &manager_id)
        .env(ENV_MANAGER_LOG_PATH, &log_path)
        .env(ENV_MANAGER_RECORD_PATH, &record_path);

    let child = child
        .spawn()
        .context("failed to spawn background morgan worker")?;
    let child_pid = child.id();
    let mut merged_record = load_record(&record_path).unwrap_or(record.clone());
    merged_record.pid = child_pid;
    if matches!(
        merged_record.status,
        ManagedProcessStatus::Launching | ManagedProcessStatus::Running
    ) {
        merged_record.status = ManagedProcessStatus::Running;
    }
    merged_record.updated_at_unix_ms = now_unix_ms();
    write_record(&record_path, &merged_record)?;

    println!("Morgan started in background.");
    println!("Manager ID: {}", merged_record.id);
    println!("PID: {}", merged_record.pid);
    println!("Command: {}", merged_record.command);
    println!("Project root: {}", merged_record.project_root.display());
    println!("Log: {}", merged_record.log_path.display());
    println!(
        "Use `morgan-manager --project-root {} status` to monitor.",
        project_root.display()
    );
    Ok(())
}

fn run_generate(args: GenerateArgs) -> Result<()> {
    let project_root = args
        .project_root
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", args.project_root.display()))?;

    let prompt = resolve_prompt(args.master_prompt, args.prompt_file, &project_root)?;
    let artifacts = resolve_script_artifacts(
        &project_root,
        &prompt,
        &args.input_files,
        args.artifact_name.as_deref(),
        args.artifact_plan_file.as_deref(),
        args.max_input_bytes,
    )?;
    let target_branches = collect_target_branches(&artifacts);
    let script = generate_script(&ScriptSpec {
        artifacts,
        engine: args.engine,
        variants: args.variants,
        sprints: args.sprints,
        keep_best: args.keep_best,
    });

    let script_path = resolve_against(&project_root, &args.script_output);
    write_file(&script_path, &script)?;
    write_target_branch_sidecar(&script_path, &target_branches)?;

    if !args.skip_lint {
        let manifest = resolve_against(&project_root, &args.julietscript_manifest);
        lint_script(&script_path, &manifest)?;
    }

    let plans = parse_execution_plans(&script)?;
    println!(
        "Generated script at {}\nEngine: {}\nVariants: {}\nSprints: {}\nKeep best: {}\nArtifacts: {}",
        script_path.display(),
        args.engine,
        args.variants.max(1),
        args.sprints.max(1),
        args.keep_best.max(1),
        plans.len()
    );
    Ok(())
}

fn run_full_run(args: RunArgs) -> Result<()> {
    let project_root = args
        .project_root
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", args.project_root.display()))?;
    let prompt = resolve_prompt(args.master_prompt, args.prompt_file, &project_root)?;
    let artifacts = resolve_script_artifacts(
        &project_root,
        &prompt,
        &args.input_files,
        args.artifact_name.as_deref(),
        args.artifact_plan_file.as_deref(),
        args.max_input_bytes,
    )?;
    let target_branches = collect_target_branches(&artifacts);

    let script = generate_script(&ScriptSpec {
        artifacts,
        engine: args.engine,
        variants: args.variants,
        sprints: args.sprints,
        keep_best: args.keep_best,
    });
    let script_path = resolve_against(&project_root, &args.script_output);
    write_file(&script_path, &script)?;
    write_target_branch_sidecar(&script_path, &target_branches)?;
    if !args.skip_lint {
        let manifest = resolve_against(&project_root, &args.julietscript_manifest);
        lint_script(&script_path, &manifest)?;
    }

    let summary = run_script(ExecuteScriptOptions {
        project_root,
        role_name: args.role,
        project_name: args.project_name,
        script_path: args.script_output,
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

    let _ = mark_current_process_run_id(&summary.run_id);
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

    let _ = mark_current_process_run_id(&summary.run_id);
    print_summary(&summary);
    Ok(())
}

fn run_resume(args: ResumeArgs) -> Result<()> {
    let summary = resume_run(ResumeRunOptions {
        project_root: args.project_root,
        run_id: args.run_id,
    })?;
    let _ = mark_current_process_run_id(&summary.run_id);
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

fn resolve_script_artifacts(
    project_root: &Path,
    master_prompt: &str,
    default_input_files: &[PathBuf],
    artifact_name: Option<&str>,
    artifact_plan_file: Option<&Path>,
    max_input_bytes: usize,
) -> Result<Vec<ScriptArtifactSpec>> {
    let _ = max_input_bytes;
    let Some(plan_path) = artifact_plan_file else {
        let name = artifact_name.unwrap_or(DEFAULT_ARTIFACT_NAME);
        validate_artifact_name(name)?;
        ensure_input_files_exist(project_root, default_input_files)?;
        let source_files = prepare_artifact_source_files(
            project_root,
            name,
            master_prompt,
            None,
            default_input_files,
            0,
        )?;
        return Ok(vec![ScriptArtifactSpec {
            artifact_name: name.to_string(),
            create_prompt: format_source_files_prompt(&source_files),
            source_files,
            dependencies: Vec::new(),
            target_branch: None,
        }]);
    };

    let resolved_plan = resolve_against(project_root, plan_path);
    let raw = fs::read_to_string(&resolved_plan).with_context(|| {
        format!(
            "failed to read artifact plan file {}",
            resolved_plan.display()
        )
    })?;
    let plan: ArtifactPlanFile = serde_json::from_str(&raw).with_context(|| {
        format!(
            "failed to parse artifact plan JSON {}",
            resolved_plan.display()
        )
    })?;
    if plan.artifacts.is_empty() {
        bail!(
            "artifact plan file {} does not include any artifacts",
            resolved_plan.display()
        );
    }

    let mut artifacts = Vec::with_capacity(plan.artifacts.len());
    for entry in plan.artifacts {
        validate_artifact_name(&entry.name)?;

        let dependencies = merge_dependencies(&entry.dependencies, &entry.using);
        for dependency in &dependencies {
            validate_artifact_name(dependency)?;
        }

        let input_files = if entry.input_files.is_empty() {
            default_input_files.to_vec()
        } else {
            entry.input_files
        };
        ensure_input_files_exist(project_root, &input_files)?;
        let source_files = prepare_artifact_source_files(
            project_root,
            &entry.name,
            master_prompt,
            entry.prompt.as_deref(),
            &input_files,
            artifacts.len(),
        )?;
        let create_prompt = format_source_files_prompt(&source_files);

        let target_branch = entry
            .target_branch
            .as_ref()
            .map(|branch| branch.trim().to_string());
        if let Some(branch) = target_branch.as_deref() {
            validate_target_branch(branch)?;
        }

        artifacts.push(ScriptArtifactSpec {
            artifact_name: entry.name,
            create_prompt,
            source_files,
            dependencies,
            target_branch,
        });
    }

    Ok(artifacts)
}

fn merge_dependencies(primary: &[String], secondary: &[String]) -> Vec<String> {
    let mut merged = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for dep in primary.iter().chain(secondary.iter()) {
        let trimmed = dep.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            merged.push(trimmed.to_string());
        }
    }
    merged
}

fn collect_target_branches(artifacts: &[ScriptArtifactSpec]) -> BTreeMap<String, String> {
    artifacts
        .iter()
        .filter_map(|artifact| {
            artifact
                .target_branch
                .as_ref()
                .map(|branch| (artifact.artifact_name.clone(), branch.trim().to_string()))
        })
        .collect()
}

fn target_branch_sidecar_path(script_path: &Path) -> Result<PathBuf> {
    let file_name = script_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("script path is not valid UTF-8")?;
    Ok(script_path.with_file_name(format!("{file_name}.morgan-target-branches.json")))
}

fn write_target_branch_sidecar(
    script_path: &Path,
    target_branches: &BTreeMap<String, String>,
) -> Result<()> {
    let sidecar_path = target_branch_sidecar_path(script_path)?;
    if target_branches.is_empty() {
        if sidecar_path.exists() {
            fs::remove_file(&sidecar_path)
                .with_context(|| format!("failed to remove {}", sidecar_path.display()))?;
        }
        return Ok(());
    }

    let payload = TargetBranchSidecar {
        target_branches: target_branches.clone(),
    };
    let encoded =
        serde_json::to_string_pretty(&payload).context("failed to serialize target sidecar")?;
    write_file(&sidecar_path, &encoded)
}

fn ensure_input_files_exist(project_root: &Path, input_files: &[PathBuf]) -> Result<()> {
    for file in input_files {
        let resolved = resolve_against(project_root, file);
        if !resolved.exists() {
            bail!("input file does not exist: {}", resolved.display());
        }
        if !resolved.is_file() {
            bail!("input path is not a file: {}", resolved.display());
        }
        fs::File::open(&resolved)
            .with_context(|| format!("input file is not readable: {}", resolved.display()))?;
    }
    Ok(())
}

fn prepare_artifact_source_files(
    project_root: &Path,
    artifact_name: &str,
    master_prompt: &str,
    artifact_prompt: Option<&str>,
    input_files: &[PathBuf],
    index: usize,
) -> Result<Vec<String>> {
    let slug = slugify(artifact_name);
    let instruction_rel = format!(
        ".morgan/source-files/{:02}-{}-instructions.md",
        index + 1,
        slug
    );
    let instruction_abs = resolve_against(project_root, Path::new(&instruction_rel));
    let resolved_input_files = input_files
        .iter()
        .map(|path| resolve_against(project_root, path))
        .collect::<Vec<_>>();
    let source_listing = if input_files.is_empty() {
        "(none)".to_string()
    } else {
        resolved_input_files
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    };
    let instructions = format!(
        "# Artifact Instructions: {artifact_name}\n\n## Master Prompt\n\n{master_prompt}\n\n## Artifact Prompt\n\n{artifact_prompt}\n\n## Source Files\n\n{source_listing}\n\n## Operational Requirements\n\n- Run preflight checks before sprint launches.\n- Ask for review when a human decision is required.\n- If branches drift or mismatch, stop and ask for branch clarification before continuing.\n- Grade sprint results using the rubric before selecting winners.\n",
        artifact_name = artifact_name,
        master_prompt = master_prompt.trim(),
        artifact_prompt = artifact_prompt.unwrap_or(master_prompt).trim(),
        source_listing = source_listing
    );
    write_file(&instruction_abs, &instructions)?;

    let mut files = Vec::with_capacity(1 + input_files.len());
    files.push(instruction_abs.to_string_lossy().to_string());
    files.extend(
        resolved_input_files
            .iter()
            .map(|path| path.to_string_lossy().to_string()),
    );
    Ok(files)
}

fn format_source_files_prompt(source_files: &[String]) -> String {
    format!(
        "Artifact source files:\n{}",
        source_files
            .iter()
            .map(|file| format!("- {}", file))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn slugify(input: &str) -> String {
    let mut output = String::new();
    let mut last_dash = false;
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            output.push('-');
            last_dash = true;
        }
    }
    output.trim_matches('-').to_string()
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn resolve_script_artifacts_defaults_to_single_generated_artifact() {
        let temp = tempdir().expect("tempdir");
        fs::write(temp.path().join("spec.md"), "alpha").expect("write input");

        let artifacts = resolve_script_artifacts(
            temp.path(),
            "master prompt",
            &[PathBuf::from("spec.md")],
            None,
            None,
            12_000,
        )
        .expect("artifacts should resolve");

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact_name, DEFAULT_ARTIFACT_NAME);
        assert_eq!(artifacts[0].target_branch, None);
        assert!(!artifacts[0].source_files.is_empty());
        assert!(artifacts[0].source_files[0].contains("/.morgan/source-files/"));
        assert!(artifacts[0].source_files[1].ends_with("/spec.md"));
        assert!(artifacts[0].dependencies.is_empty());
        assert!(
            artifacts[0]
                .create_prompt
                .contains("Artifact source files:")
        );
    }

    #[test]
    fn resolve_script_artifacts_loads_multi_artifact_plan_file() {
        let temp = tempdir().expect("tempdir");
        fs::write(temp.path().join("phase1.md"), "phase1").expect("write phase1");
        fs::write(temp.path().join("phase2.md"), "phase2").expect("write phase2");
        fs::write(
            temp.path().join("plan.json"),
            r#"{
  "artifacts": [
    {
      "name": "Phase1",
      "prompt": "Build phase one",
      "input_files": ["phase1.md"],
      "target_branch": "feature/phase-1"
    },
    {
      "name": "Phase2",
      "input_files": ["phase2.md"],
      "using": ["Phase1"],
      "target_branch": "feature/phase-2"
    }
  ]
}"#,
        )
        .expect("write plan");

        let artifacts = resolve_script_artifacts(
            temp.path(),
            "global prompt",
            &[],
            Some("ignored"),
            Some(Path::new("plan.json")),
            12_000,
        )
        .expect("artifacts should resolve");

        assert_eq!(artifacts.len(), 2);
        assert_eq!(artifacts[0].artifact_name, "Phase1");
        assert_eq!(
            artifacts[0].target_branch.as_deref(),
            Some("feature/phase-1")
        );
        assert!(
            artifacts[0]
                .create_prompt
                .contains("Artifact source files:")
        );
        assert!(
            artifacts[0]
                .source_files
                .iter()
                .any(|file| file.ends_with("/phase1.md"))
        );
        assert_eq!(artifacts[1].artifact_name, "Phase2");
        assert_eq!(artifacts[1].dependencies, vec!["Phase1".to_string()]);
        assert_eq!(
            artifacts[1].target_branch.as_deref(),
            Some("feature/phase-2")
        );
        assert!(
            artifacts[1]
                .create_prompt
                .contains("Artifact source files:")
        );
        assert!(
            artifacts[1]
                .source_files
                .iter()
                .any(|file| file.ends_with("/phase2.md"))
        );
    }
}
