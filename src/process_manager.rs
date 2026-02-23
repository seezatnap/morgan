use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::run_memory::now_unix_ms;

pub const ENV_FOREGROUND_WORKER: &str = "MORGAN_FOREGROUND_WORKER";
pub const ENV_MANAGER_ID: &str = "MORGAN_MANAGER_ID";
pub const ENV_MANAGER_LOG_PATH: &str = "MORGAN_MANAGER_LOG_PATH";
pub const ENV_MANAGER_RECORD_PATH: &str = "MORGAN_MANAGER_RECORD_PATH";

const LOGS_DIR: &str = ".morgan/logs";
const RECORDS_DIR: &str = ".morgan/manager/processes";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedProcessStatus {
    Launching,
    Running,
    Exited,
    Failed,
    Killed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedProcessRecord {
    pub id: String,
    pub pid: u32,
    pub command: String,
    pub project_root: PathBuf,
    pub log_path: PathBuf,
    pub run_id: Option<String>,
    pub status: ManagedProcessStatus,
    pub exit_code: Option<i32>,
    pub started_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

pub fn ensure_manager_dirs(project_root: &Path) -> Result<()> {
    fs::create_dir_all(logs_dir(project_root))
        .with_context(|| format!("failed to create {}", logs_dir(project_root).display()))?;
    fs::create_dir_all(records_dir(project_root))
        .with_context(|| format!("failed to create {}", records_dir(project_root).display()))?;
    Ok(())
}

pub fn logs_dir(project_root: &Path) -> PathBuf {
    project_root.join(LOGS_DIR)
}

pub fn records_dir(project_root: &Path) -> PathBuf {
    project_root.join(RECORDS_DIR)
}

pub fn record_path(project_root: &Path, manager_id: &str) -> PathBuf {
    records_dir(project_root).join(format!("{manager_id}.json"))
}

pub fn write_record(path: &Path, record: &ManagedProcessRecord) -> Result<()> {
    let encoded =
        serde_json::to_string_pretty(record).context("failed to encode process record")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, encoded).with_context(|| format!("failed to write {}", path.display()))
}

pub fn load_record(path: &Path) -> Result<ManagedProcessRecord> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn list_records(project_root: &Path) -> Result<Vec<(PathBuf, ManagedProcessRecord)>> {
    let dir = records_dir(project_root);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut records = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let record = match load_record(&path) {
            Ok(record) => record,
            Err(_) => continue,
        };
        records.push((path, record));
    }
    records.sort_by(|(_, left), (_, right)| right.started_at_unix_ms.cmp(&left.started_at_unix_ms));
    Ok(records)
}

pub fn generate_manager_id() -> String {
    format!("mgr-{}-{}", now_unix_ms(), std::process::id())
}

pub fn is_foreground_worker() -> bool {
    std::env::var(ENV_FOREGROUND_WORKER).as_deref() == Ok("1")
}

pub fn current_manager_id() -> Option<String> {
    std::env::var(ENV_MANAGER_ID)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn current_log_path() -> Option<PathBuf> {
    std::env::var(ENV_MANAGER_LOG_PATH)
        .ok()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

pub fn current_record_path() -> Option<PathBuf> {
    std::env::var(ENV_MANAGER_RECORD_PATH)
        .ok()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

pub fn mark_current_process_running() -> Result<()> {
    update_current_record(|record| {
        record.status = ManagedProcessStatus::Running;
        Ok(())
    })
}

pub fn mark_current_process_run_id(run_id: &str) -> Result<()> {
    let run_id = run_id.trim();
    if run_id.is_empty() {
        bail!("run_id cannot be empty");
    }

    update_current_record(|record| {
        record.run_id = Some(run_id.to_string());
        Ok(())
    })
}

pub fn mark_current_process_exited(exit_code: i32) -> Result<()> {
    update_current_record(|record| {
        record.exit_code = Some(exit_code);
        record.status = if record.status == ManagedProcessStatus::Killed {
            ManagedProcessStatus::Killed
        } else if exit_code == 0 {
            ManagedProcessStatus::Exited
        } else {
            ManagedProcessStatus::Failed
        };
        Ok(())
    })
}

pub fn save_record_status(
    path: &Path,
    status: ManagedProcessStatus,
    exit_code: Option<i32>,
) -> Result<()> {
    let mut record = load_record(path)?;
    record.status = status;
    record.exit_code = exit_code;
    record.updated_at_unix_ms = now_unix_ms();
    write_record(path, &record)
}

fn update_current_record<F>(mut update: F) -> Result<()>
where
    F: FnMut(&mut ManagedProcessRecord) -> Result<()>,
{
    let Some(path) = current_record_path() else {
        return Ok(());
    };
    if !path.is_file() {
        return Ok(());
    }

    let mut record = load_record(&path)?;
    update(&mut record)?;
    record.updated_at_unix_ms = now_unix_ms();
    write_record(&path, &record)
}

pub fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }

    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub fn send_signal(pid: u32, signal: &str) -> Result<()> {
    let signal = signal.trim();
    if signal.is_empty() {
        bail!("signal cannot be empty");
    }

    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to send {signal} to pid {pid}"))?;
    if status.success() {
        return Ok(());
    }

    bail!("kill -{signal} {pid} failed")
}
