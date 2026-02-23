use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{ArgAction, Parser, Subcommand};

use morgan::process_manager::{
    ManagedProcessRecord, ManagedProcessStatus, is_process_alive, list_records, load_record,
    record_path, save_record_status, send_signal, write_record,
};
use morgan::run_memory::{RunState, RunStatus, now_unix_ms};

#[derive(Debug, Parser)]
#[command(
    name = "morgan-manager",
    version,
    about = "Manage background Morgan workers"
)]
struct Cli {
    /// Root directory containing `.morgan`.
    #[arg(long, default_value = ".")]
    project_root: PathBuf,

    #[command(subcommand)]
    command: Option<ManagerCommand>,
}

#[derive(Debug, Subcommand)]
enum ManagerCommand {
    /// Print a status table for Morgan workers.
    Status(StatusArgs),
    /// Stop a worker by manager ID or run ID.
    Kill(KillArgs),
    /// Print the log path for a worker by manager ID or run ID.
    Logs(IdArgs),
    /// Remove stale process records for non-running workers.
    Cleanup(CleanupArgs),
}

#[derive(Debug, Parser)]
struct StatusArgs {
    /// Include non-running workers.
    #[arg(long, default_value_t = false, action = ArgAction::SetTrue)]
    all: bool,
}

#[derive(Debug, Parser)]
struct KillArgs {
    /// Manager ID (`mgr-...`) or run ID (`run-...`).
    #[arg(long)]
    id: String,

    /// Seconds to wait after TERM before forcing KILL.
    #[arg(long, default_value_t = 5)]
    grace_seconds: u64,
}

#[derive(Debug, Parser)]
struct IdArgs {
    /// Manager ID (`mgr-...`) or run ID (`run-...`).
    #[arg(long)]
    id: String,
}

#[derive(Debug, Parser)]
struct CleanupArgs {
    /// Remove non-running worker log files along with record files.
    #[arg(long, default_value_t = false, action = ArgAction::SetTrue)]
    remove_logs: bool,
}

#[derive(Debug, Clone)]
struct RunSnapshot {
    run_id: String,
    manager_id: Option<String>,
    status: RunStatus,
    morgan_pid: Option<u32>,
    log_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct Candidate {
    path: Option<PathBuf>,
    record: ManagedProcessRecord,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("morgan-manager: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let project_root = cli
        .project_root
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", cli.project_root.display()))?;
    let command = cli
        .command
        .unwrap_or(ManagerCommand::Status(StatusArgs { all: false }));

    match command {
        ManagerCommand::Status(args) => run_status(&project_root, args),
        ManagerCommand::Kill(args) => run_kill(&project_root, args),
        ManagerCommand::Logs(args) => run_logs(&project_root, args),
        ManagerCommand::Cleanup(args) => run_cleanup(&project_root, args),
    }
}

fn run_status(project_root: &Path, args: StatusArgs) -> Result<()> {
    let snapshots = load_run_snapshots(project_root)?;
    let by_manager = snapshots_by_manager(&snapshots);
    let mut records = list_records(project_root)?;
    let now = now_unix_ms();
    let mut rows = Vec::new();

    for (path, mut record) in records.drain(..) {
        if record.run_id.is_none()
            && let Some(snapshot) = by_manager.get(&record.id)
        {
            record.run_id = Some(snapshot.run_id.clone());
            record.updated_at_unix_ms = now;
            write_record(&path, &record)?;
        }

        let alive = is_process_alive(record.pid);
        if !args.all && !alive {
            continue;
        }

        let run_status = resolve_run_status(&record, &snapshots);
        let age = format_age_seconds(now.saturating_sub(record.started_at_unix_ms));
        rows.push(vec![
            record.id,
            record.pid.to_string(),
            record.run_id.unwrap_or_else(|| "-".to_string()),
            record.command,
            if alive {
                "alive".to_string()
            } else {
                "dead".to_string()
            },
            run_status,
            age,
            record.log_path.display().to_string(),
        ]);
    }

    if rows.is_empty() {
        if args.all {
            println!("No Morgan process records found.");
        } else {
            println!("No running Morgan workers found.");
        }
        return Ok(());
    }

    print_table(
        &["ID", "PID", "RUN ID", "CMD", "PROC", "RUN", "AGE", "LOG"],
        &rows,
    );
    Ok(())
}

fn run_kill(project_root: &Path, args: KillArgs) -> Result<()> {
    let snapshots = load_run_snapshots(project_root)?;
    let candidates = resolve_candidate(project_root, &args.id, &snapshots)?;
    let pid = candidates.record.pid;

    if !is_process_alive(pid) {
        if let Some(path) = &candidates.path {
            let _ = save_record_status(path, ManagedProcessStatus::Exited, None);
        }
        println!(
            "Worker {} is not running (pid {}).",
            candidates.record.id, candidates.record.pid
        );
        return Ok(());
    }

    send_signal(pid, "TERM")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(args.grace_seconds.max(1));
    while std::time::Instant::now() < deadline {
        if !is_process_alive(pid) {
            break;
        }
        thread::sleep(Duration::from_millis(150));
    }

    let mut forced = false;
    if is_process_alive(pid) {
        forced = true;
        send_signal(pid, "KILL")?;
        let hard_deadline = std::time::Instant::now() + Duration::from_secs(1);
        while std::time::Instant::now() < hard_deadline {
            if !is_process_alive(pid) {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    if is_process_alive(pid) {
        bail!("worker process {} is still alive after kill attempts", pid);
    }

    if let Some(path) = &candidates.path {
        let _ = save_record_status(path, ManagedProcessStatus::Killed, None);
    }

    println!(
        "Stopped worker {} (pid {}, forced: {}).",
        candidates.record.id, pid, forced
    );
    if let Some(run_id) = candidates.record.run_id {
        println!("Run ID: {run_id}");
    }
    Ok(())
}

fn run_logs(project_root: &Path, args: IdArgs) -> Result<()> {
    let snapshots = load_run_snapshots(project_root)?;
    let candidate = resolve_candidate(project_root, &args.id, &snapshots)?;
    println!("{}", candidate.record.log_path.display());
    Ok(())
}

fn run_cleanup(project_root: &Path, args: CleanupArgs) -> Result<()> {
    let mut removed_records = 0usize;
    let mut removed_logs = 0usize;

    for (path, record) in list_records(project_root)? {
        if is_process_alive(record.pid) {
            continue;
        }

        fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
        removed_records += 1;

        if args.remove_logs && record.log_path.is_file() {
            fs::remove_file(&record.log_path)
                .with_context(|| format!("failed to remove {}", record.log_path.display()))?;
            removed_logs += 1;
        }
    }

    println!(
        "Removed {} stale record(s) and {} log file(s).",
        removed_records, removed_logs
    );
    Ok(())
}

fn resolve_candidate(
    project_root: &Path,
    id: &str,
    snapshots: &[RunSnapshot],
) -> Result<Candidate> {
    for (path, record) in list_records(project_root)? {
        if record.id == id || record.run_id.as_deref() == Some(id) {
            return Ok(Candidate {
                path: Some(path),
                record,
            });
        }
    }

    let by_manager = snapshots_by_manager(snapshots);
    if let Some(snapshot) = by_manager.get(id)
        && let Some(pid) = snapshot.morgan_pid
    {
        let path = Some(record_path(project_root, id));
        let record = if let Some(path) = &path {
            if path.is_file() {
                load_record(path)?
            } else {
                synthesize_record(project_root, snapshot, id, pid)
            }
        } else {
            synthesize_record(project_root, snapshot, id, pid)
        };
        return Ok(Candidate { path, record });
    }

    if let Some(snapshot) = snapshots.iter().find(|snapshot| snapshot.run_id == id)
        && let Some(pid) = snapshot.morgan_pid
    {
        let manager_id = snapshot
            .manager_id
            .clone()
            .unwrap_or_else(|| format!("run-{id}"));
        let path = snapshot
            .manager_id
            .as_deref()
            .map(|manager_id| record_path(project_root, manager_id))
            .filter(|path| path.is_file());
        let record = if let Some(path) = &path {
            load_record(path)?
        } else {
            synthesize_record(project_root, snapshot, &manager_id, pid)
        };
        return Ok(Candidate { path, record });
    }

    bail!("no worker found for ID '{id}'")
}

fn synthesize_record(
    project_root: &Path,
    snapshot: &RunSnapshot,
    manager_id: &str,
    pid: u32,
) -> ManagedProcessRecord {
    ManagedProcessRecord {
        id: manager_id.to_string(),
        pid,
        command: "run".to_string(),
        project_root: project_root.to_path_buf(),
        log_path: snapshot
            .log_path
            .clone()
            .unwrap_or_else(|| project_root.join(".morgan/logs/unknown.log")),
        run_id: Some(snapshot.run_id.clone()),
        status: ManagedProcessStatus::Running,
        exit_code: None,
        started_at_unix_ms: now_unix_ms(),
        updated_at_unix_ms: now_unix_ms(),
    }
}

fn resolve_run_status(record: &ManagedProcessRecord, snapshots: &[RunSnapshot]) -> String {
    if let Some(run_id) = &record.run_id
        && let Some(snapshot) = snapshots.iter().find(|snapshot| &snapshot.run_id == run_id)
    {
        return run_status_label(&snapshot.status);
    }
    if let Some(snapshot) = snapshots
        .iter()
        .find(|snapshot| snapshot.manager_id.as_deref() == Some(record.id.as_str()))
    {
        return run_status_label(&snapshot.status);
    }
    "-".to_string()
}

fn run_status_label(status: &RunStatus) -> String {
    match status {
        RunStatus::InProgress => "in_progress".to_string(),
        RunStatus::Completed => "completed".to_string(),
        RunStatus::Failed => "failed".to_string(),
    }
}

fn format_age_seconds(delta_ms: u64) -> String {
    format!("{}s", delta_ms / 1000)
}

fn snapshots_by_manager(snapshots: &[RunSnapshot]) -> HashMap<String, RunSnapshot> {
    let mut map = HashMap::new();
    for snapshot in snapshots {
        if let Some(manager_id) = &snapshot.manager_id {
            map.insert(manager_id.clone(), snapshot.clone());
        }
    }
    map
}

fn load_run_snapshots(project_root: &Path) -> Result<Vec<RunSnapshot>> {
    let runs_dir = project_root.join(".morgan").join("runs");
    if !runs_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut snapshots = Vec::new();
    for entry in
        fs::read_dir(&runs_dir).with_context(|| format!("failed to read {}", runs_dir.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read entry in {}", runs_dir.display()))?;
        let state_path = entry.path().join("state.json");
        if !state_path.is_file() {
            continue;
        }

        let raw = match fs::read_to_string(&state_path) {
            Ok(raw) => raw,
            Err(_) => continue,
        };
        let state = match serde_json::from_str::<RunState>(&raw) {
            Ok(state) => state,
            Err(_) => continue,
        };
        snapshots.push(RunSnapshot {
            run_id: state.run_id,
            manager_id: state.manager_id,
            status: state.status,
            morgan_pid: state.morgan_pid,
            log_path: state.log_path,
        });
    }
    Ok(snapshots)
}

fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths = headers
        .iter()
        .map(|header| header.len())
        .collect::<Vec<_>>();
    for row in rows {
        for (idx, cell) in row.iter().enumerate() {
            if idx >= widths.len() {
                widths.push(cell.len());
            } else {
                widths[idx] = widths[idx].max(cell.len());
            }
        }
    }

    print_row(
        &headers
            .iter()
            .map(|header| header.to_string())
            .collect::<Vec<_>>(),
        &widths,
    );
    let divider = widths
        .iter()
        .map(|width| "-".repeat(*width))
        .collect::<Vec<_>>()
        .join("-+-");
    println!("{divider}");

    for row in rows {
        print_row(row, &widths);
    }
}

fn print_row(row: &[String], widths: &[usize]) {
    let rendered = row
        .iter()
        .enumerate()
        .map(|(idx, cell)| format!("{:width$}", cell, width = widths[idx]))
        .collect::<Vec<_>>()
        .join(" | ");
    println!("{rendered}");
}
