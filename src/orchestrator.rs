use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::codex::{CodexAction, classify_juliet_output, ensure_codex_ready};
use crate::engine::Engine;
use crate::git;
use crate::juliet::{JulietClient, JulietRunner};
use crate::julietscript::{
    ExecutionPlan, ScriptSpec, generate_script, lint_script, parse_execution_plans,
    validate_artifact_name,
};
use crate::preflight::{PreflightOptions, load_input_context, run_preflight};
use crate::run_memory::{
    ActiveArtifactState, RunExecutionConfig, RunState, RunStatus, RunStore, load_run_state,
};

#[derive(Debug, Clone)]
pub struct RunGeneratedOptions {
    pub project_root: PathBuf,
    pub role_name: String,
    pub project_name: String,
    pub artifact_name: String,
    pub master_prompt: String,
    pub input_files: Vec<PathBuf>,
    pub script_output: PathBuf,
    pub engine: Engine,
    pub variants: u32,
    pub sprints: u32,
    pub keep_best: u32,
    pub source_branch: Option<String>,
    pub juliet_bin: Option<PathBuf>,
    pub juliet_manifest: Option<PathBuf>,
    pub julietscript_manifest: Option<PathBuf>,
    pub heartbeat_seconds: u64,
    pub max_turns: u32,
    pub email: Option<String>,
    pub auto_fix_branches: bool,
    pub auto_grade: bool,
    pub lint_enabled: bool,
    pub max_input_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct ExecuteScriptOptions {
    pub project_root: PathBuf,
    pub role_name: String,
    pub project_name: String,
    pub script_path: PathBuf,
    pub source_branch: Option<String>,
    pub juliet_bin: Option<PathBuf>,
    pub juliet_manifest: Option<PathBuf>,
    pub julietscript_manifest: Option<PathBuf>,
    pub heartbeat_seconds: u64,
    pub max_turns: u32,
    pub email: Option<String>,
    pub auto_fix_branches: bool,
    pub auto_grade: bool,
    pub lint_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct ResumeRunOptions {
    pub project_root: PathBuf,
    pub run_id: String,
}

#[derive(Debug, Clone)]
pub struct ReplayRunOptions {
    pub project_root: PathBuf,
    pub run_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub run_id: String,
    pub script_path: PathBuf,
    pub prd_path: PathBuf,
    pub completed: bool,
    pub resume_id: Option<String>,
    pub turns: Vec<TurnRecord>,
    pub artifact_runs: Vec<ArtifactRunSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayTurnSummary {
    pub artifact_name: String,
    pub turn: u32,
    pub original_signal: JulietSignal,
    pub replayed_signal: JulietSignal,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySummary {
    pub run_id: String,
    pub total_turns: usize,
    pub changed_turns: usize,
    pub turns: Vec<ReplayTurnSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRunSummary {
    pub artifact_name: String,
    pub dependencies: Vec<String>,
    pub source_branch: String,
    pub target_branch: String,
    #[serde(default)]
    pub execution_root: Option<PathBuf>,
    pub prd_path: PathBuf,
    pub completed: bool,
    pub resume_id: Option<String>,
    pub turns: Vec<TurnRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnRecord {
    pub artifact_name: String,
    pub turn: u32,
    pub sent: String,
    pub received: String,
    pub signal: JulietSignal,
    #[serde(default)]
    pub raw_signal: Option<JulietSignal>,
    #[serde(default)]
    pub decision_source: Option<DecisionSource>,
    #[serde(default)]
    pub decision_rule: Option<String>,
    #[serde(default)]
    pub classifier_error: Option<String>,
    pub source_branch: String,
    pub target_branch: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JulietSignal {
    NeedsEmail,
    NeedsTaskReview,
    StillWorking,
    ResultsReview,
    ResultsComplete,
    BranchClarification,
    Idle,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionSource {
    Codex,
    HeuristicFallback,
    GuardrailOverride,
}

#[derive(Debug, Clone)]
struct DecisionTrace {
    raw_signal: JulietSignal,
    final_signal: JulietSignal,
    source: DecisionSource,
    rule: Option<String>,
    classifier_error: Option<String>,
}

pub fn run_generated(options: RunGeneratedOptions) -> Result<RunSummary> {
    let project_root = options
        .project_root
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", options.project_root.display()))?;

    validate_artifact_name(&options.artifact_name)?;

    let preflight = run_preflight(&PreflightOptions {
        project_root: project_root.clone(),
        input_files: options.input_files.clone(),
        source_branch: options.source_branch.clone(),
        julietscript_manifest: options.julietscript_manifest.clone(),
        lint_enabled: options.lint_enabled,
    })?;

    let input_context =
        load_input_context(&project_root, &options.input_files, options.max_input_bytes)?;
    let script = generate_script(&ScriptSpec {
        artifact_name: options.artifact_name.clone(),
        master_prompt: options.master_prompt.clone(),
        input_context,
        engine: options.engine,
        variants: options.variants,
        sprints: options.sprints,
        keep_best: options.keep_best,
    });

    let script_path = resolve_against(&project_root, &options.script_output);
    write_file(&script_path, &script)?;

    if options.lint_enabled {
        let manifest = resolve_lint_manifest(&project_root, options.julietscript_manifest.as_ref());
        lint_script(&script_path, &manifest)?;
    }

    let plans = parse_execution_plans(&script)?;

    run_with_plans(RunWithPlansOptions {
        project_root,
        role_name: options.role_name,
        project_name: options.project_name,
        script_path,
        plans,
        initial_source_branch: preflight.source_branch,
        juliet_bin: options.juliet_bin,
        juliet_manifest: options.juliet_manifest,
        heartbeat_seconds: options.heartbeat_seconds,
        max_turns: options.max_turns,
        email: options.email,
        auto_fix_branches: options.auto_fix_branches,
        auto_grade: options.auto_grade,
        resume_state: None,
    })
}

pub fn run_script(options: ExecuteScriptOptions) -> Result<RunSummary> {
    let project_root = options
        .project_root
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", options.project_root.display()))?;

    let script_path = resolve_against(&project_root, &options.script_path);
    let script_contents = fs::read_to_string(&script_path)
        .with_context(|| format!("failed to read {}", script_path.display()))?;

    let preflight = run_preflight(&PreflightOptions {
        project_root: project_root.clone(),
        input_files: Vec::new(),
        source_branch: options.source_branch.clone(),
        julietscript_manifest: options.julietscript_manifest.clone(),
        lint_enabled: options.lint_enabled,
    })?;

    if options.lint_enabled {
        let manifest = resolve_lint_manifest(&project_root, options.julietscript_manifest.as_ref());
        lint_script(&script_path, &manifest)?;
    }

    let plans = parse_execution_plans(&script_contents)?;

    run_with_plans(RunWithPlansOptions {
        project_root,
        role_name: options.role_name,
        project_name: options.project_name,
        script_path,
        plans,
        initial_source_branch: preflight.source_branch,
        juliet_bin: options.juliet_bin,
        juliet_manifest: options.juliet_manifest,
        heartbeat_seconds: options.heartbeat_seconds,
        max_turns: options.max_turns,
        email: options.email,
        auto_fix_branches: options.auto_fix_branches,
        auto_grade: options.auto_grade,
        resume_state: None,
    })
}

pub fn resume_run(options: ResumeRunOptions) -> Result<RunSummary> {
    let project_root = options
        .project_root
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", options.project_root.display()))?;

    let (_, state) = load_run_state(&project_root, &options.run_id)?;
    if state.status == RunStatus::Completed {
        bail!(
            "run '{}' is already completed. use `morgan replay --run-id {}` to inspect it.",
            state.run_id,
            state.run_id
        );
    }
    if state.status == RunStatus::Failed {
        bail!(
            "run '{}' is marked failed. inspect {} before retrying.",
            state.run_id,
            state.run_dir().display()
        );
    }

    run_with_plans(RunWithPlansOptions {
        project_root: state.project_root.clone(),
        role_name: state.role_name.clone(),
        project_name: state.project_name.clone(),
        script_path: state.script_path.clone(),
        plans: state.plans.clone(),
        initial_source_branch: state.current_source_branch.clone(),
        juliet_bin: state.config.juliet_bin.clone(),
        juliet_manifest: state.config.juliet_manifest.clone(),
        heartbeat_seconds: state.config.heartbeat_seconds,
        max_turns: state.config.max_turns,
        email: state.config.email.clone(),
        auto_fix_branches: state.config.auto_fix_branches,
        auto_grade: state.config.auto_grade,
        resume_state: Some(state),
    })
}

pub fn replay_run(options: ReplayRunOptions) -> Result<ReplaySummary> {
    let project_root = options
        .project_root
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", options.project_root.display()))?;
    let (_, state) = load_run_state(&project_root, &options.run_id)?;
    if let Err(err) = ensure_codex_ready(&state.project_root) {
        eprintln!(
            "morgan: warning: codex classifier readiness check failed during replay; using heuristic fallback where needed: {err:#}"
        );
    }

    let mut turn_summaries = Vec::with_capacity(state.turns.len());
    for turn in &state.turns {
        let replayed_signal =
            classify_response_hybrid(&state.project_root, &turn.received).final_signal;
        turn_summaries.push(ReplayTurnSummary {
            artifact_name: turn.artifact_name.clone(),
            turn: turn.turn,
            changed: replayed_signal != turn.signal,
            original_signal: turn.signal,
            replayed_signal,
        });
    }

    let changed_turns = turn_summaries.iter().filter(|turn| turn.changed).count();
    Ok(ReplaySummary {
        run_id: state.run_id,
        total_turns: turn_summaries.len(),
        changed_turns,
        turns: turn_summaries,
    })
}

#[derive(Debug)]
struct RunWithPlansOptions {
    project_root: PathBuf,
    role_name: String,
    project_name: String,
    script_path: PathBuf,
    plans: Vec<ExecutionPlan>,
    initial_source_branch: String,
    juliet_bin: Option<PathBuf>,
    juliet_manifest: Option<PathBuf>,
    heartbeat_seconds: u64,
    max_turns: u32,
    email: Option<String>,
    auto_fix_branches: bool,
    auto_grade: bool,
    resume_state: Option<RunState>,
}

#[derive(Debug, Clone)]
struct ArtifactResumeState {
    next_instruction: String,
    resume_id: Option<String>,
    final_grade_requested: bool,
    turns: Vec<TurnRecord>,
}

#[derive(Debug)]
struct RunTracker {
    store: RunStore,
    state: RunState,
}

impl RunTracker {
    fn new(options: &RunWithPlansOptions) -> Result<Self> {
        let state = RunState::new(
            options.project_root.clone(),
            options.role_name.clone(),
            options.project_name.clone(),
            options.script_path.clone(),
            options.plans.clone(),
            RunExecutionConfig {
                heartbeat_seconds: options.heartbeat_seconds,
                max_turns: options.max_turns,
                email: options.email.clone(),
                auto_fix_branches: options.auto_fix_branches,
                auto_grade: options.auto_grade,
                juliet_bin: options.juliet_bin.clone(),
                juliet_manifest: options.juliet_manifest.clone(),
            },
            options.initial_source_branch.clone(),
        );
        let store = RunStore::create(&options.project_root, &state)?;
        store.append_event(
            "run_started",
            &serde_json::json!({
                "run_id": state.run_id,
                "script_path": state.script_path,
            }),
        )?;
        Ok(Self { store, state })
    }

    fn from_resume(project_root: &Path, state: RunState) -> Result<Self> {
        let store = RunStore::open(project_root, &state.run_id)?;
        store.append_event(
            "run_resumed",
            &serde_json::json!({
                "run_id": state.run_id,
                "next_artifact_index": state.next_artifact_index,
            }),
        )?;
        Ok(Self { store, state })
    }

    fn mark_failed(&mut self, message: &str) -> Result<()> {
        self.state.status = RunStatus::Failed;
        self.state.status_message = Some(message.to_string());
        self.state.touch();
        self.store.save_state(&self.state)?;
        self.store.append_event(
            "run_failed",
            &serde_json::json!({
                "run_id": self.state.run_id,
                "message": message,
            }),
        )
    }

    fn mark_completed(&mut self, resume_id: Option<&str>) -> Result<()> {
        self.state.status = RunStatus::Completed;
        self.state.status_message = None;
        self.state.active_artifact = None;
        self.state.next_artifact_index = self.state.plans.len();
        if let Some(id) = resume_id {
            self.state.shared_resume_id = Some(id.to_string());
        }
        self.state.touch();
        self.store.save_state(&self.state)?;
        self.store.append_event(
            "run_completed",
            &serde_json::json!({
                "run_id": self.state.run_id,
                "artifacts": self.state.artifact_runs.len(),
                "turns": self.state.turns.len(),
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn begin_artifact(
        &mut self,
        artifact_index: usize,
        plan: &ExecutionPlan,
        source_branch: &str,
        target_branch: &str,
        next_instruction: String,
        resume_id: Option<String>,
        final_grade_requested: bool,
        turns: Vec<TurnRecord>,
    ) -> Result<()> {
        self.state.active_artifact = Some(ActiveArtifactState {
            artifact_index,
            artifact_name: plan.artifact_name.clone(),
            source_branch: source_branch.to_string(),
            target_branch: target_branch.to_string(),
            next_instruction,
            resume_id: resume_id.clone(),
            final_grade_requested,
            turns,
        });
        if let Some(id) = resume_id {
            self.state.shared_resume_id = Some(id);
        }
        self.state.touch();
        self.store.save_state(&self.state)?;
        self.store.append_event(
            "artifact_started",
            &serde_json::json!({
                "artifact_index": artifact_index,
                "artifact": plan.artifact_name,
                "source_branch": source_branch,
                "target_branch": target_branch,
            }),
        )
    }

    fn record_turn(
        &mut self,
        turn: &TurnRecord,
        next_instruction: &str,
        resume_id: Option<&str>,
        final_grade_requested: bool,
    ) -> Result<()> {
        let active = self
            .state
            .active_artifact
            .as_mut()
            .context("internal error: missing active artifact while recording turn")?;
        active.next_instruction = next_instruction.to_string();
        active.resume_id = resume_id.map(ToOwned::to_owned);
        active.final_grade_requested = final_grade_requested;
        active.turns.push(turn.clone());
        self.state.turns.push(turn.clone());
        if let Some(id) = resume_id {
            self.state.shared_resume_id = Some(id.to_string());
        }
        self.state.touch();
        self.store.save_state(&self.state)?;
        self.store.append_event(
            "turn_recorded",
            &serde_json::json!({
                "artifact": turn.artifact_name,
                "turn": turn.turn,
                "signal": turn.signal,
                "raw_signal": turn.raw_signal,
                "decision_source": turn.decision_source,
                "decision_rule": turn.decision_rule,
                "classifier_error": turn.classifier_error,
            }),
        )
    }

    fn finish_artifact(
        &mut self,
        artifact_index: usize,
        summary: &ArtifactRunSummary,
        next_source_branch: &str,
    ) -> Result<()> {
        self.state.artifact_runs.push(summary.clone());
        self.state.next_artifact_index = artifact_index + 1;
        self.state.current_source_branch = next_source_branch.to_string();
        self.state.shared_resume_id = summary.resume_id.clone();
        self.state.active_artifact = None;
        self.state.touch();
        self.store.save_state(&self.state)?;
        self.store.append_event(
            "artifact_completed",
            &serde_json::json!({
                "artifact_index": artifact_index,
                "artifact": summary.artifact_name,
                "completed": summary.completed,
                "turns": summary.turns.len(),
            }),
        )
    }
}

fn run_with_plans(options: RunWithPlansOptions) -> Result<RunSummary> {
    if options.plans.is_empty() {
        bail!("script did not produce any execution plans");
    }
    validate_dependency_order(&options.plans)?;
    if let Err(err) = ensure_codex_ready(&options.project_root) {
        eprintln!(
            "morgan: warning: codex classifier readiness check failed; continuing with heuristic fallback where needed: {err:#}"
        );
    }

    let juliet_runner = JulietRunner::discover(
        &options.project_root,
        options.juliet_bin.as_deref(),
        options.juliet_manifest.as_deref(),
    )?;

    let mut tracker = match options.resume_state {
        Some(state) => RunTracker::from_resume(&options.project_root, state)?,
        None => RunTracker::new(&options)?,
    };

    if let Some(active) = &tracker.state.active_artifact
        && active.artifact_index != tracker.state.next_artifact_index
    {
        bail!(
            "run state is inconsistent: active artifact index {} does not match next artifact index {}",
            active.artifact_index,
            tracker.state.next_artifact_index
        );
    }

    let mut used_targets = BTreeSet::new();
    let target_branches = options
        .plans
        .iter()
        .map(|plan| derive_target_branch(&plan.artifact_name, &mut used_targets))
        .collect::<Vec<_>>();

    let mut source_branch = tracker.state.current_source_branch.clone();
    let mut shared_resume_id = tracker.state.shared_resume_id.clone();
    let mut artifact_runs = tracker.state.artifact_runs.clone();
    let mut all_turns = tracker.state.turns.clone();
    let start_index = tracker.state.next_artifact_index;
    let mut active_resume = tracker.state.active_artifact.clone();
    let mut last_execution_root: Option<PathBuf> = None;

    if start_index > options.plans.len() {
        bail!(
            "run state has invalid next_artifact_index {} for {} plans",
            start_index,
            options.plans.len()
        );
    }

    for (artifact_index, (plan, target_branch)) in options
        .plans
        .iter()
        .zip(target_branches.iter())
        .enumerate()
        .skip(start_index)
    {
        let target_branch = target_branch.clone();
        let continuation = if let Some(active) = active_resume.take() {
            if active.artifact_index != artifact_index {
                bail!(
                    "run state expects active artifact index {} but execution resumed at {}",
                    active.artifact_index,
                    artifact_index
                );
            }
            if active.source_branch != source_branch || active.target_branch != target_branch {
                bail!(
                    "active artifact branch mismatch for '{}': expected {} -> {}, found {} -> {}",
                    plan.artifact_name,
                    source_branch,
                    target_branch,
                    active.source_branch,
                    active.target_branch
                );
            }
            Some(ArtifactResumeState {
                next_instruction: active.next_instruction,
                resume_id: active.resume_id,
                final_grade_requested: active.final_grade_requested,
                turns: active.turns,
            })
        } else {
            None
        };

        let existing_turn_count = continuation
            .as_ref()
            .map(|state| state.turns.len())
            .unwrap_or(0);
        let execution_root = resolve_execution_root(&options.project_root, &source_branch)?;
        let continue_id = if continuation.is_some() {
            shared_resume_id.as_deref()
        } else if let Some(previous_root) = last_execution_root.as_ref() {
            if paths_match(previous_root, &execution_root) {
                shared_resume_id.as_deref()
            } else {
                None
            }
        } else {
            None
        };
        let artifact_summary = match run_single_artifact(
            &juliet_runner,
            &execution_root,
            &options.role_name,
            &options.project_name,
            &options.script_path,
            plan,
            artifact_index,
            &source_branch,
            &target_branch,
            options.heartbeat_seconds,
            options.max_turns,
            options.email.as_deref(),
            options.auto_fix_branches,
            options.auto_grade,
            continue_id,
            continuation,
            Some(&mut tracker),
        ) {
            Ok(summary) => summary,
            Err(err) => {
                let message = format!("{err:#}");
                tracker.mark_failed(&message)?;
                return Err(err);
            }
        };

        shared_resume_id = artifact_summary.resume_id.clone();
        if existing_turn_count < artifact_summary.turns.len() {
            all_turns.extend(
                artifact_summary
                    .turns
                    .iter()
                    .skip(existing_turn_count)
                    .cloned(),
            );
        }
        let artifact_completed = artifact_summary.completed;
        if artifact_completed {
            source_branch = target_branch;
        }
        artifact_runs.push(artifact_summary);
        last_execution_root = Some(execution_root);
        if !artifact_completed {
            break;
        }
    }

    let completed = artifact_runs.iter().all(|run| run.completed);
    if completed {
        tracker.mark_completed(shared_resume_id.as_deref())?;
    }

    let last_run = artifact_runs
        .last()
        .context("internal error: artifact run list is unexpectedly empty")?;

    Ok(RunSummary {
        run_id: tracker.state.run_id.clone(),
        script_path: options.script_path,
        prd_path: last_run.prd_path.clone(),
        completed,
        resume_id: last_run.resume_id.clone(),
        turns: all_turns,
        artifact_runs,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_single_artifact(
    juliet_runner: &JulietRunner,
    execution_root: &Path,
    role_name: &str,
    project_name: &str,
    script_path: &Path,
    plan: &ExecutionPlan,
    artifact_index: usize,
    source_branch: &str,
    target_branch: &str,
    heartbeat_seconds: u64,
    max_turns: u32,
    email: Option<&str>,
    auto_fix_branches: bool,
    auto_grade: bool,
    continue_id: Option<&str>,
    continuation: Option<ArtifactResumeState>,
    mut tracker: Option<&mut RunTracker>,
) -> Result<ArtifactRunSummary> {
    let client = JulietClient::new(juliet_runner.clone(), execution_root, role_name);
    client.ensure_role_initialized()?;

    let current_branch = git::current_branch(execution_root)?;
    if source_branch != current_branch && !auto_fix_branches {
        if let Some(other_worktree) = git::worktree_for_branch(execution_root, source_branch)?
            && !paths_match(execution_root, &other_worktree)
        {
            bail!(
                "source branch '{}' for artifact '{}' is checked out at worktree '{}'. Re-run from that worktree or enable --auto-fix-branches.",
                source_branch,
                plan.artifact_name,
                other_worktree.display()
            );
        }
        bail!(
            "current branch '{}' does not match source branch '{}' for artifact '{}'. Enable --auto-fix-branches or align manually.",
            current_branch,
            source_branch,
            plan.artifact_name
        );
    }

    if source_branch != current_branch && auto_fix_branches {
        if git::branch_exists(execution_root, source_branch)? {
            git::checkout(execution_root, source_branch)?;
        } else {
            git::create_branch(execution_root, source_branch, Some(&current_branch))?;
        }
    }

    let prd_path = write_master_prd(
        execution_root,
        role_name,
        project_name,
        script_path,
        plan,
        source_branch,
        target_branch,
    )?;

    let mut kickoff = format!(
        "start artifact {} from prd path {}. use source branch {} and target branch {}. execution workspace: {}.",
        plan.artifact_name,
        prd_path.display(),
        source_branch,
        target_branch,
        execution_root.display()
    );
    if !plan.dependencies.is_empty() {
        kickoff.push_str(&format!(
            " this artifact depends on [{}].",
            plan.dependencies.join(", ")
        ));
    }

    let (mut next_instruction, mut resume_id, mut final_grade_requested, mut turns) =
        if let Some(state) = continuation {
            (
                state.next_instruction,
                state
                    .resume_id
                    .or_else(|| continue_id.map(ToOwned::to_owned)),
                state.final_grade_requested,
                state.turns,
            )
        } else {
            (
                kickoff,
                continue_id.map(ToOwned::to_owned),
                false,
                Vec::new(),
            )
        };

    if let Some(run_tracker) = tracker.as_mut() {
        run_tracker.begin_artifact(
            artifact_index,
            plan,
            source_branch,
            target_branch,
            next_instruction.clone(),
            resume_id.clone(),
            final_grade_requested,
            turns.clone(),
        )?;
    }

    let mut completed = false;
    let starting_turn = turns
        .last()
        .map(|record| record.turn.saturating_add(1))
        .unwrap_or(1);
    for turn in starting_turn..=max_turns {
        let outbound = compose_turn_message(&next_instruction, plan, source_branch, target_branch);
        let response = client.exec_turn(plan.engine, &outbound, resume_id.as_deref())?;
        resume_id = Some(response.resume_id.clone());
        let decision = classify_response_hybrid(execution_root, &response.text);
        let signal = decision.final_signal;

        let turn_record = TurnRecord {
            artifact_name: plan.artifact_name.clone(),
            turn,
            sent: outbound,
            received: response.text.clone(),
            signal,
            raw_signal: Some(decision.raw_signal),
            decision_source: Some(decision.source),
            decision_rule: decision.rule.clone(),
            classifier_error: decision.classifier_error.clone(),
            source_branch: source_branch.to_string(),
            target_branch: target_branch.to_string(),
        };
        turns.push(turn_record.clone());

        let mut should_break = false;
        match signal {
            JulietSignal::NeedsEmail => {
                let email = email.context(
                    "juliet requested .swarm-hug/email.txt but no --email value was supplied",
                )?;
                next_instruction = format!(
                    "use this email value for .swarm-hug/email.txt: {}",
                    email.trim()
                );
            }
            JulietSignal::NeedsTaskReview => {
                next_instruction = format!(
                    "tasks look good. use {}. run {} variations and {} sprints. use source branch {} and target branch {}.",
                    plan.engine, plan.variants, plan.sprints, source_branch, target_branch
                );
            }
            JulietSignal::StillWorking | JulietSignal::Unknown | JulietSignal::Idle => {
                if turn < max_turns {
                    thread::sleep(Duration::from_secs(heartbeat_seconds.max(1)));
                    next_instruction = "status update please.".to_string();
                }
            }
            JulietSignal::ResultsReview => {
                if auto_grade {
                    next_instruction = "grade these results using your rubric, summarize winner branches, and continue to the next sprint if work remains.".to_string();
                } else {
                    next_instruction = "looks good. continue to the next sprint.".to_string();
                }
            }
            JulietSignal::ResultsComplete => {
                if auto_grade && !final_grade_requested {
                    next_instruction = "before we finish, grade the final results with your rubric and summarize the winning branch.".to_string();
                    final_grade_requested = true;
                } else {
                    completed = true;
                    should_break = true;
                }
            }
            JulietSignal::BranchClarification => {
                next_instruction = repair_branches_and_respond(
                    execution_root,
                    source_branch,
                    target_branch,
                    auto_fix_branches,
                )?;
            }
        }

        if let Some(run_tracker) = tracker.as_mut() {
            run_tracker.record_turn(
                &turn_record,
                &next_instruction,
                resume_id.as_deref(),
                final_grade_requested,
            )?;
        }

        if should_break {
            break;
        }
    }

    let summary = ArtifactRunSummary {
        artifact_name: plan.artifact_name.clone(),
        dependencies: plan.dependencies.clone(),
        source_branch: source_branch.to_string(),
        target_branch: target_branch.to_string(),
        execution_root: Some(execution_root.to_path_buf()),
        prd_path,
        completed,
        resume_id,
        turns,
    };

    if summary.completed
        && let Some(run_tracker) = tracker.as_mut()
    {
        run_tracker.finish_artifact(artifact_index, &summary, target_branch)?;
    }

    Ok(summary)
}

fn compose_turn_message(
    instruction: &str,
    plan: &ExecutionPlan,
    source_branch: &str,
    target_branch: &str,
) -> String {
    let dependencies = if plan.dependencies.is_empty() {
        "(none)".to_string()
    } else {
        plan.dependencies.join(", ")
    };

    format!(
        "{instruction}\n\nExecution context:\n- artifact: {}\n- source branch: {}\n- destination branch: {}\n- target branch: {}\n- dependencies: {}",
        plan.artifact_name, source_branch, target_branch, target_branch, dependencies
    )
}

fn resolve_execution_root(project_root: &Path, source_branch: &str) -> Result<PathBuf> {
    let Some(worktree_path) = git::worktree_for_branch(project_root, source_branch)? else {
        return Ok(project_root.to_path_buf());
    };
    if paths_match(project_root, &worktree_path) {
        Ok(project_root.to_path_buf())
    } else {
        Ok(worktree_path)
    }
}

fn paths_match(left: &Path, right: &Path) -> bool {
    let left = left.canonicalize().unwrap_or_else(|_| left.to_path_buf());
    let right = right.canonicalize().unwrap_or_else(|_| right.to_path_buf());
    left == right
}

fn classify_response_hybrid(project_root: &Path, text: &str) -> DecisionTrace {
    let (raw_signal, classifier_error) = match classify_response_with_codex(project_root, text) {
        Ok(signal) => (signal, None),
        Err(err) => (classify_response_heuristic(text), Some(format!("{err:#}"))),
    };

    classify_response_hybrid_with_raw(raw_signal, text, classifier_error)
}

fn classify_response_hybrid_with_raw(
    raw_signal: JulietSignal,
    text: &str,
    classifier_error: Option<String>,
) -> DecisionTrace {
    if let Some((override_signal, rule)) = guardrail_override_signal(text)
        && override_signal != raw_signal
    {
        return DecisionTrace {
            raw_signal,
            final_signal: override_signal,
            source: DecisionSource::GuardrailOverride,
            rule: Some(rule.to_string()),
            classifier_error,
        };
    }

    DecisionTrace {
        raw_signal,
        final_signal: raw_signal,
        source: if classifier_error.is_some() {
            DecisionSource::HeuristicFallback
        } else {
            DecisionSource::Codex
        },
        rule: None,
        classifier_error,
    }
}

fn classify_response_with_codex(project_root: &Path, text: &str) -> Result<JulietSignal> {
    let action = classify_juliet_output(project_root, text)?;
    Ok(match action {
        CodexAction::NeedsEmail => JulietSignal::NeedsEmail,
        CodexAction::NeedsTaskReview => JulietSignal::NeedsTaskReview,
        CodexAction::StillWorking => JulietSignal::StillWorking,
        CodexAction::ResultsReview => JulietSignal::ResultsReview,
        CodexAction::ResultsComplete => JulietSignal::ResultsComplete,
        CodexAction::BranchClarification => JulietSignal::BranchClarification,
        CodexAction::Idle => JulietSignal::Idle,
        CodexAction::Unknown => JulietSignal::Unknown,
    })
}

fn guardrail_override_signal(text: &str) -> Option<(JulietSignal, &'static str)> {
    let lower = text.to_ascii_lowercase();
    if lower.contains(".swarm-hug/email.txt") {
        return Some((JulietSignal::NeedsEmail, "email_request"));
    }
    if lower.contains("which branch to use")
        || lower.contains("branch clarification")
        || (lower.contains("branch") && lower.contains("differs"))
        || lower.contains("source branch")
            && (lower.contains("does not match")
                || lower.contains("can't continue")
                || lower.contains("cannot continue"))
    {
        return Some((JulietSignal::BranchClarification, "branch_mismatch"));
    }
    if lower.contains("look at these tasks:")
        || (lower.contains("how many variations") && lower.contains("how many sprints"))
    {
        return Some((JulietSignal::NeedsTaskReview, "task_review_prompt"));
    }
    None
}

fn classify_response_heuristic(text: &str) -> JulietSignal {
    let lower = text.to_ascii_lowercase();
    if lower.contains("before i start sprints, what email should i save in .swarm-hug/email.txt?") {
        return JulietSignal::NeedsEmail;
    }
    if lower.contains("look at these tasks:")
        || (lower.contains("how many variations") && lower.contains("how many sprints"))
    {
        return JulietSignal::NeedsTaskReview;
    }
    if lower.contains("i'm still working") || lower.contains("im still working") {
        return JulietSignal::StillWorking;
    }
    if lower.contains("here's the results:") && lower.contains("looks like everything's done") {
        return JulietSignal::ResultsComplete;
    }
    if lower.contains("here's the results:") {
        return JulietSignal::ResultsReview;
    }
    if lower.contains("which branch to use")
        || lower.contains("branch clarification")
        || (lower.contains("branch") && lower.contains("differs"))
    {
        return JulietSignal::BranchClarification;
    }
    if lower.contains("what do you want to work on today") {
        return JulietSignal::Idle;
    }
    JulietSignal::Unknown
}

fn repair_branches_and_respond(
    project_root: &Path,
    source_branch: &str,
    target_branch: &str,
    auto_fix_branches: bool,
) -> Result<String> {
    if !auto_fix_branches {
        bail!(
            "juliet requested branch clarification. Re-run with --auto-fix-branches or resolve manually."
        );
    }

    let current = git::current_branch(project_root)?;
    if current == source_branch {
        return Ok(format!(
            "use source branch {} and target branch {}.",
            source_branch, target_branch
        ));
    }

    if let Some(other_worktree) = git::worktree_for_branch(project_root, source_branch)?
        && !paths_match(project_root, &other_worktree)
    {
        return Ok(format!(
            "source branch {} is checked out in worktree {}. continue there with source branch {} and target branch {}.",
            source_branch,
            other_worktree.display(),
            source_branch,
            target_branch
        ));
    }

    if git::branch_exists(project_root, source_branch)? {
        git::checkout(project_root, source_branch)?;
        return Ok(format!(
            "i switched to source branch {}. continue with source branch {} and target branch {}.",
            source_branch, source_branch, target_branch
        ));
    }

    git::create_branch(project_root, source_branch, Some(&current))?;
    Ok(format!(
        "i created source branch {} from {}. continue with source branch {} and target branch {}.",
        source_branch, current, source_branch, target_branch
    ))
}

fn validate_dependency_order(plans: &[ExecutionPlan]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for plan in plans {
        if !seen.insert(plan.artifact_name.clone()) {
            bail!(
                "duplicate artifact '{}' in create statements; artifact names must be unique for ordered execution",
                plan.artifact_name
            );
        }
        for dependency in &plan.dependencies {
            if !seen.contains(dependency) {
                bail!(
                    "artifact '{}' depends on '{}' which is not defined earlier in the script. Define dependencies before dependents.",
                    plan.artifact_name,
                    dependency
                );
            }
        }
    }
    Ok(())
}

fn derive_target_branch(artifact_name: &str, used_targets: &mut BTreeSet<String>) -> String {
    let base = format!("feature/{}", slugify(artifact_name));
    if used_targets.insert(base.clone()) {
        return base;
    }

    let mut suffix = 2u32;
    loop {
        let candidate = format!("{base}-{suffix}");
        if used_targets.insert(candidate.clone()) {
            return candidate;
        }
        suffix += 1;
    }
}

fn write_master_prd(
    project_root: &Path,
    role_name: &str,
    project_name: &str,
    script_path: &Path,
    plan: &ExecutionPlan,
    source_branch: &str,
    target_branch: &str,
) -> Result<PathBuf> {
    let artifacts_dir = project_root
        .join(".juliet")
        .join(role_name)
        .join("artifacts");
    fs::create_dir_all(&artifacts_dir)
        .with_context(|| format!("failed to create {}", artifacts_dir.display()))?;

    let project_slug = slugify(project_name);
    let artifact_slug = slugify(&plan.artifact_name);
    let prd_path = artifacts_dir.join(format!("{project_slug}-{artifact_slug}-morgan-prd.md"));
    let dependencies = if plan.dependencies.is_empty() {
        "(none)".to_string()
    } else {
        plan.dependencies.join(", ")
    };
    let contents = format!(
        "# {project_name} - {}\n\n## Master Prompt\n\n{}\n\n## Branch Context\n\n- source branch: {}\n- target branch: {}\n- dependencies: {}\n\n## Generated JulietScript\n\n- {}\n",
        plan.artifact_name,
        plan.create_prompt,
        source_branch,
        target_branch,
        dependencies,
        script_path.display()
    );

    fs::write(&prd_path, contents)
        .with_context(|| format!("failed to write {}", prd_path.display()))?;
    Ok(prd_path)
}

fn resolve_lint_manifest(project_root: &Path, manifest: Option<&PathBuf>) -> PathBuf {
    manifest
        .map(|path| resolve_against(project_root, path))
        .unwrap_or_else(|| project_root.join("../julietscript/Cargo.toml"))
}

fn write_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))
}

fn resolve_against(base: &Path, candidate: &Path) -> PathBuf {
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    }
}

fn slugify(input: &str) -> String {
    let re = Regex::new(r#"[^a-z0-9]+"#).unwrap();
    let lowered = input.to_ascii_lowercase();
    let slug = re.replace_all(&lowered, "-");
    slug.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(name: &str, deps: &[&str]) -> ExecutionPlan {
        ExecutionPlan {
            artifact_name: name.to_string(),
            engine: Engine::Codex,
            variants: 1,
            sprints: 1,
            keep_best: 1,
            create_prompt: "x".to_string(),
            dependencies: deps.iter().map(|dep| dep.to_string()).collect(),
        }
    }

    #[test]
    fn heuristic_classifier_detects_review_and_completion_states() {
        assert_eq!(
            classify_response_heuristic("look at these tasks: .swarm-hug/foo/tasks.md"),
            JulietSignal::NeedsTaskReview
        );
        assert_eq!(
            classify_response_heuristic("i'm still working"),
            JulietSignal::StillWorking
        );
        assert_eq!(
            classify_response_heuristic(
                "here's the results: path. if you're happy with them, i'll move on to the next sprint."
            ),
            JulietSignal::ResultsReview
        );
        assert_eq!(
            classify_response_heuristic(
                "here's the results: path. looks like everything's done - let me know if you'd like any changes."
            ),
            JulietSignal::ResultsComplete
        );
    }

    #[test]
    fn guardrail_overrides_completion_when_email_is_requested() {
        let trace = classify_response_hybrid_with_raw(
            JulietSignal::ResultsComplete,
            "looks done. before i start sprints, what email should i save in .swarm-hug/email.txt?",
            None,
        );
        assert_eq!(trace.raw_signal, JulietSignal::ResultsComplete);
        assert_eq!(trace.final_signal, JulietSignal::NeedsEmail);
        assert_eq!(trace.source, DecisionSource::GuardrailOverride);
        assert_eq!(trace.rule.as_deref(), Some("email_request"));
    }

    #[test]
    fn fallback_trace_marks_classifier_error() {
        let trace = classify_response_hybrid_with_raw(
            JulietSignal::StillWorking,
            "i'm still working",
            Some("codex unavailable".to_string()),
        );
        assert_eq!(trace.final_signal, JulietSignal::StillWorking);
        assert_eq!(trace.source, DecisionSource::HeuristicFallback);
        assert_eq!(trace.classifier_error.as_deref(), Some("codex unavailable"));
    }

    #[test]
    fn slugify_normalizes_free_text() {
        assert_eq!(slugify("Feature: CLI Builder"), "feature-cli-builder");
    }

    #[test]
    fn validates_dependency_order_by_appearance() {
        let valid = vec![plan("A", &[]), plan("B", &["A"]), plan("C", &["A", "B"])];
        assert!(validate_dependency_order(&valid).is_ok());

        let invalid = vec![plan("B", &["A"]), plan("A", &[])];
        assert!(validate_dependency_order(&invalid).is_err());
    }

    #[test]
    fn derives_unique_target_branches_for_duplicate_artifacts() {
        let mut used = BTreeSet::new();
        let first = derive_target_branch("Feature One", &mut used);
        let second = derive_target_branch("Feature One", &mut used);
        assert_eq!(first, "feature/feature-one");
        assert_eq!(second, "feature/feature-one-2");
    }
}
