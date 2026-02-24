use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::julietscript::ExecutionPlan;
use crate::orchestrator::{ArtifactRunSummary, TurnRecord};
use crate::process_manager::{current_log_path, current_manager_id};

const STATE_FILE: &str = "state.json";
const EVENTS_FILE: &str = "events.jsonl";
const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunExecutionConfig {
    pub heartbeat_seconds: u64,
    pub max_turns: u32,
    pub email: Option<String>,
    pub auto_fix_branches: bool,
    pub auto_grade: bool,
    pub juliet_bin: Option<PathBuf>,
    pub juliet_manifest: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    InProgress,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveArtifactState {
    pub artifact_index: usize,
    pub artifact_name: String,
    pub source_branch: String,
    pub target_branch: String,
    #[serde(default = "default_sprint_cycle")]
    pub sprint_cycle: u32,
    pub next_instruction: String,
    pub resume_id: Option<String>,
    pub final_grade_requested: bool,
    pub turns: Vec<TurnRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunState {
    pub version: u32,
    pub run_id: String,
    pub project_root: PathBuf,
    pub role_name: String,
    pub project_name: String,
    pub script_path: PathBuf,
    pub plans: Vec<ExecutionPlan>,
    pub config: RunExecutionConfig,
    pub current_source_branch: String,
    pub next_artifact_index: usize,
    pub shared_resume_id: Option<String>,
    pub status: RunStatus,
    pub status_message: Option<String>,
    pub started_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    #[serde(default)]
    pub manager_id: Option<String>,
    #[serde(default)]
    pub morgan_pid: Option<u32>,
    #[serde(default)]
    pub log_path: Option<PathBuf>,
    pub artifact_runs: Vec<ArtifactRunSummary>,
    pub turns: Vec<TurnRecord>,
    pub active_artifact: Option<ActiveArtifactState>,
}

impl RunState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_root: PathBuf,
        role_name: String,
        project_name: String,
        script_path: PathBuf,
        plans: Vec<ExecutionPlan>,
        config: RunExecutionConfig,
        initial_source_branch: String,
    ) -> Self {
        let now = now_unix_ms();
        let manager_id = current_manager_id();
        let log_path = current_log_path();
        Self {
            version: STATE_VERSION,
            run_id: generate_run_id(),
            project_root,
            role_name,
            project_name,
            script_path,
            plans,
            config,
            current_source_branch: initial_source_branch,
            next_artifact_index: 0,
            shared_resume_id: None,
            status: RunStatus::InProgress,
            status_message: None,
            started_at_unix_ms: now,
            updated_at_unix_ms: now,
            manager_id,
            morgan_pid: Some(process::id()),
            log_path,
            artifact_runs: Vec::new(),
            turns: Vec::new(),
            active_artifact: None,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at_unix_ms = now_unix_ms();
    }

    pub fn run_dir(&self) -> PathBuf {
        run_dir(&self.project_root, &self.run_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunEvent {
    pub timestamp_unix_ms: u64,
    pub kind: String,
    pub payload: Value,
}

#[derive(Debug, Clone)]
pub struct RunStore {
    pub run_id: String,
    pub run_dir: PathBuf,
    state_path: PathBuf,
    events_path: PathBuf,
}

impl RunStore {
    pub fn create(project_root: &Path, state: &RunState) -> Result<Self> {
        if state.run_id.trim().is_empty() {
            bail!("run_id cannot be empty");
        }

        let run_dir = run_dir(project_root, &state.run_id);
        fs::create_dir_all(&run_dir)
            .with_context(|| format!("failed to create {}", run_dir.display()))?;

        let store = Self::from_dir(state.run_id.clone(), run_dir);
        store.save_state(state)?;
        Ok(store)
    }

    pub fn open(project_root: &Path, run_id: &str) -> Result<Self> {
        let run_dir = run_dir(project_root, run_id);
        if !run_dir.is_dir() {
            bail!("run directory does not exist: {}", run_dir.display());
        }
        Ok(Self::from_dir(run_id.to_string(), run_dir))
    }

    pub fn load_state(&self) -> Result<RunState> {
        let raw = fs::read_to_string(&self.state_path)
            .with_context(|| format!("failed to read {}", self.state_path.display()))?;
        let mut state: RunState = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse {}", self.state_path.display()))?;
        if state.version != STATE_VERSION {
            bail!(
                "unsupported run state version {} in {} (expected {})",
                state.version,
                self.state_path.display(),
                STATE_VERSION
            );
        }
        // Ensure run_id aligns with storage path, even if a hand-edited file drifts.
        state.run_id = self.run_id.clone();
        Ok(state)
    }

    pub fn save_state(&self, state: &RunState) -> Result<()> {
        let encoded =
            serde_json::to_string_pretty(state).context("failed to serialize run state")?;
        fs::write(&self.state_path, encoded)
            .with_context(|| format!("failed to write {}", self.state_path.display()))
    }

    pub fn append_event<T: Serialize>(&self, kind: &str, payload: &T) -> Result<()> {
        let event = RunEvent {
            timestamp_unix_ms: now_unix_ms(),
            kind: kind.to_string(),
            payload: serde_json::to_value(payload)
                .context("failed to serialize run event payload")?,
        };
        let encoded = serde_json::to_string(&event).context("failed to serialize run event")?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.events_path)
            .with_context(|| format!("failed to open {}", self.events_path.display()))?;
        writeln!(file, "{encoded}")
            .with_context(|| format!("failed to append {}", self.events_path.display()))
    }

    pub fn load_events(&self) -> Result<Vec<RunEvent>> {
        if !self.events_path.is_file() {
            return Ok(Vec::new());
        }
        let file = fs::File::open(&self.events_path)
            .with_context(|| format!("failed to read {}", self.events_path.display()))?;
        let mut events = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line.context("failed to read event line")?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let event: RunEvent = serde_json::from_str(trimmed)
                .with_context(|| format!("failed to parse run event: {trimmed}"))?;
            events.push(event);
        }
        Ok(events)
    }

    fn from_dir(run_id: String, run_dir: PathBuf) -> Self {
        Self {
            run_id,
            state_path: run_dir.join(STATE_FILE),
            events_path: run_dir.join(EVENTS_FILE),
            run_dir,
        }
    }
}

pub fn load_run_state(project_root: &Path, run_id: &str) -> Result<(RunStore, RunState)> {
    let store = RunStore::open(project_root, run_id)?;
    let state = store.load_state()?;
    Ok((store, state))
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn generate_run_id() -> String {
    let unix_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("run-{unix_nanos}-{}", process::id())
}

fn run_dir(project_root: &Path, run_id: &str) -> PathBuf {
    project_root.join(".morgan").join("runs").join(run_id)
}

fn default_sprint_cycle() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::tempdir;

    use crate::engine::Engine;
    use crate::julietscript::ExecutionPlan;

    fn sample_plan() -> ExecutionPlan {
        ExecutionPlan {
            artifact_name: "ArtifactA".to_string(),
            engine: Engine::Codex,
            variants: 1,
            sprints: 1,
            keep_best: 1,
            create_prompt: "Ship it".to_string(),
            source_files: Vec::new(),
            dependencies: Vec::new(),
            target_branch: None,
        }
    }

    #[test]
    fn create_and_reload_run_state() {
        let temp = tempdir().expect("tempdir");
        let state = RunState::new(
            temp.path().to_path_buf(),
            "doe".to_string(),
            "project".to_string(),
            temp.path().join(".morgan/generated.julietscript"),
            vec![sample_plan()],
            RunExecutionConfig {
                heartbeat_seconds: 5,
                max_turns: 10,
                email: Some("test@example.com".to_string()),
                auto_fix_branches: true,
                auto_grade: true,
                juliet_bin: None,
                juliet_manifest: None,
            },
            "main".to_string(),
        );

        let store = RunStore::create(temp.path(), &state).expect("create store");
        let loaded = store.load_state().expect("load state");
        assert_eq!(loaded.run_id, state.run_id);
        assert_eq!(loaded.project_name, "project");
        assert_eq!(loaded.next_artifact_index, 0);
    }

    #[test]
    fn appends_and_loads_events() {
        let temp = tempdir().expect("tempdir");
        let state = RunState::new(
            temp.path().to_path_buf(),
            "doe".to_string(),
            "project".to_string(),
            temp.path().join(".morgan/generated.julietscript"),
            vec![sample_plan()],
            RunExecutionConfig {
                heartbeat_seconds: 5,
                max_turns: 10,
                email: None,
                auto_fix_branches: true,
                auto_grade: true,
                juliet_bin: None,
                juliet_manifest: None,
            },
            "main".to_string(),
        );

        let store = RunStore::create(temp.path(), &state).expect("create store");
        store
            .append_event("run_started", &serde_json::json!({"run_id": state.run_id}))
            .expect("append event");
        store
            .append_event("turn_recorded", &serde_json::json!({"turn": 1}))
            .expect("append event");

        let events = store.load_events().expect("load events");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, "run_started");
        assert_eq!(events[1].kind, "turn_recorded");
    }
}
