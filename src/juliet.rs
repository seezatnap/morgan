use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;

use crate::engine::Engine;

#[derive(Debug, Clone)]
pub enum JulietRunner {
    Binary(PathBuf),
    CargoManifest(PathBuf),
}

#[derive(Debug, Clone)]
pub struct JulietClient {
    runner: JulietRunner,
    project_root: PathBuf,
    role_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResponse {
    pub text: String,
    pub resume_id: String,
    pub engine: Engine,
}

#[derive(Debug, Deserialize)]
struct ExecEnvelope {
    text: String,
    resume_id: String,
    engine: String,
}

impl JulietClient {
    pub fn new(
        runner: JulietRunner,
        project_root: impl Into<PathBuf>,
        role_name: impl Into<String>,
    ) -> Self {
        Self {
            runner,
            project_root: project_root.into(),
            role_name: role_name.into(),
        }
    }

    pub fn ensure_role_initialized(&self) -> Result<()> {
        let output = self.run_juliet(["init", "--project", self.role_name.as_str()])?;
        if output.status.success() {
            return Ok(());
        }

        bail!(
            "juliet init failed (exit {}):\nstdout:\n{}\nstderr:\n{}",
            output.status.code().unwrap_or(1),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    pub fn exec_turn(
        &self,
        engine: Engine,
        message: &str,
        continue_id: Option<&str>,
    ) -> Result<ExecResponse> {
        let mut args = vec![
            "exec".to_string(),
            "--json".to_string(),
            "--project".to_string(),
            self.role_name.clone(),
        ];

        if let Some(id) = continue_id {
            args.push("--continue".to_string());
            args.push(id.to_string());
        }

        args.push(engine.as_juliet_str().to_string());
        args.push(message.to_string());

        let output = self.run_juliet_dynamic(&args)?;
        if !output.status.success() {
            bail!(
                "juliet exec failed (exit {}):\nstdout:\n{}\nstderr:\n{}",
                output.status.code().unwrap_or(1),
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        parse_exec_response(&output.stdout)
    }

    fn run_juliet<const N: usize>(&self, args: [&str; N]) -> Result<Output> {
        let args = args
            .iter()
            .map(|arg| arg.to_string())
            .collect::<Vec<String>>();
        self.run_juliet_dynamic(&args)
    }

    fn run_juliet_dynamic(&self, args: &[String]) -> Result<Output> {
        let mut cmd = match &self.runner {
            JulietRunner::Binary(binary) => {
                let mut cmd = Command::new(binary);
                for arg in args {
                    cmd.arg(arg);
                }
                cmd
            }
            JulietRunner::CargoManifest(manifest_path) => {
                let mut cmd = Command::new("cargo");
                cmd.arg("run")
                    .arg("--quiet")
                    .arg("--manifest-path")
                    .arg(manifest_path)
                    .arg("--");
                for arg in args {
                    cmd.arg(arg);
                }
                cmd
            }
        };

        cmd.current_dir(&self.project_root)
            .output()
            .with_context(|| {
                format!(
                    "failed to launch juliet command from {}",
                    self.project_root.display()
                )
            })
    }
}

impl JulietRunner {
    pub fn discover(
        project_root: &Path,
        juliet_bin: Option<&Path>,
        juliet_manifest: Option<&Path>,
    ) -> Result<Self> {
        if let Some(bin) = juliet_bin {
            return Ok(Self::Binary(bin.to_path_buf()));
        }

        if command_exists("juliet", ["--version"]) {
            return Ok(Self::Binary(PathBuf::from("juliet")));
        }

        let sibling_binary = project_root.join("../juliet/target/debug/juliet");
        if sibling_binary.is_file() {
            return Ok(Self::Binary(sibling_binary));
        }

        let manifest = juliet_manifest
            .map(PathBuf::from)
            .unwrap_or_else(|| project_root.join("../juliet/Cargo.toml"));
        if manifest.is_file() {
            return Ok(Self::CargoManifest(manifest));
        }

        bail!(
            "unable to locate juliet binary. Install 'juliet', build ../juliet/target/debug/juliet, or provide --juliet-bin/--juliet-manifest"
        );
    }
}

fn parse_exec_response(stdout: &[u8]) -> Result<ExecResponse> {
    let raw = String::from_utf8_lossy(stdout);
    let mut parsed = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            parsed = Some(value);
        }
    }

    if parsed.is_none() {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            parsed = serde_json::from_str::<Value>(trimmed).ok();
        }
    }

    let value = parsed.context("juliet returned no parseable JSON output for exec --json")?;
    let envelope: ExecEnvelope =
        serde_json::from_value(value).context("juliet exec JSON envelope is malformed")?;
    let engine = Engine::parse(&envelope.engine)
        .with_context(|| format!("juliet returned unsupported engine '{}'", envelope.engine))?;

    Ok(ExecResponse {
        text: envelope.text,
        resume_id: envelope.resume_id,
        engine,
    })
}

fn command_exists<const N: usize>(program: &str, args: [&str; N]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_exec_response_reads_json_line() {
        let payload = br#"{"text":"hello","resume_id":"abc123","engine":"codex"}"#;
        let parsed = parse_exec_response(payload).expect("exec envelope should parse");
        assert_eq!(
            parsed,
            ExecResponse {
                text: "hello".to_string(),
                resume_id: "abc123".to_string(),
                engine: Engine::Codex
            }
        );
    }

    #[test]
    fn parse_exec_response_rejects_missing_fields() {
        let payload = br#"{"text":"hello"}"#;
        assert!(parse_exec_response(payload).is_err());
    }
}
