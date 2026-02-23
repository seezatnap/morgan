use std::io;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexAction {
    NeedsEmail,
    NeedsTaskReview,
    StillWorking,
    ResultsReview,
    ResultsComplete,
    BranchClarification,
    Idle,
    Unknown,
}

#[derive(Debug, Deserialize)]
struct ActionEnvelope {
    action: String,
}

pub fn ensure_codex_ready(cwd: &Path) -> Result<()> {
    let output = Command::new("codex")
        .arg("login")
        .arg("status")
        .current_dir(cwd)
        .output()
        .map_err(|err| match err.kind() {
            io::ErrorKind::NotFound => anyhow::anyhow!(
                "codex CLI is not installed or not on PATH. Install Codex before running orchestration."
            ),
            _ => anyhow::anyhow!("failed to run `codex login status`: {err}"),
        })?;

    if !output.status.success() {
        bail!(
            "`codex login status` failed (exit {}):\n{}",
            output.status.code().unwrap_or(1),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("Logged in using") {
        bail!(
            "Codex is not ready. Expected `codex login status` to contain `Logged in using` but got:\n{}",
            stdout.trim()
        );
    }

    Ok(())
}

pub fn classify_juliet_output(cwd: &Path, juliet_output: &str) -> Result<CodexAction> {
    let prompt = build_classifier_prompt(juliet_output);
    let output = Command::new("codex")
        .arg("exec")
        .arg(prompt)
        .arg("--json")
        .arg("--skip-git-repo-check")
        .current_dir(cwd)
        .output()
        .with_context(|| format!("failed to execute `codex exec` in {}", cwd.display()))?;

    if !output.status.success() {
        bail!(
            "`codex exec` classifier failed (exit {}):\n{}",
            output.status.code().unwrap_or(1),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let agent_message = extract_last_agent_message(&output.stdout)
        .context("classifier did not return an agent_message result")?;
    parse_action_from_message(&agent_message)
}

fn build_classifier_prompt(juliet_output: &str) -> String {
    format!(
        "Classify the most appropriate next action from JULIET_OUTPUT only.\nReturn ONLY compact JSON with shape {{\"action\":\"<label>\"}}.\nAllowed labels: needs_email, needs_task_review, still_working, results_review, results_complete, branch_clarification, idle, unknown.\n\nJULIET_OUTPUT:\n{}",
        juliet_output
    )
}

fn extract_last_agent_message(stdout: &[u8]) -> Option<String> {
    let raw = String::from_utf8_lossy(stdout);
    let mut last_agent_message = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if value.get("type").and_then(Value::as_str) == Some("item.completed")
            && value.pointer("/item/type").and_then(Value::as_str) == Some("agent_message")
        {
            last_agent_message = value
                .pointer("/item/text")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
        }
    }

    last_agent_message
}

fn parse_action_from_message(message: &str) -> Result<CodexAction> {
    if let Ok(envelope) = serde_json::from_str::<ActionEnvelope>(message) {
        return map_action_label(&envelope.action);
    }

    // If model wrapped JSON in extra text, pull the first object-looking segment.
    let object_re = Regex::new(r#"\{[\s\S]*\}"#).unwrap();
    if let Some(found) = object_re.find(message) {
        let snippet = found.as_str();
        if let Ok(envelope) = serde_json::from_str::<ActionEnvelope>(snippet) {
            return map_action_label(&envelope.action);
        }
    }

    bail!(
        "unable to parse classifier action JSON from message: {}",
        message
    )
}

fn map_action_label(label: &str) -> Result<CodexAction> {
    let normalized = label.trim().to_ascii_lowercase().replace('-', "_");
    let action = match normalized.as_str() {
        "needs_email" => CodexAction::NeedsEmail,
        "needs_task_review" => CodexAction::NeedsTaskReview,
        "still_working" => CodexAction::StillWorking,
        "results_review" => CodexAction::ResultsReview,
        "results_complete" => CodexAction::ResultsComplete,
        "branch_clarification" => CodexAction::BranchClarification,
        "idle" => CodexAction::Idle,
        "unknown" => CodexAction::Unknown,
        other => bail!("unsupported classifier action label '{}'", other),
    };
    Ok(action)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_direct_json_action() {
        let action =
            parse_action_from_message(r#"{"action":"needs_task_review"}"#).expect("should parse");
        assert_eq!(action, CodexAction::NeedsTaskReview);
    }

    #[test]
    fn parses_embedded_json_action() {
        let action = parse_action_from_message(
            "The best action is:\n{\"action\":\"results_complete\"}\nProceed.",
        )
        .expect("should parse embedded json");
        assert_eq!(action, CodexAction::ResultsComplete);
    }

    #[test]
    fn extracts_last_agent_message_from_codex_stream() {
        let stream = br#"{"type":"thread.started","thread_id":"t1"}
{"type":"item.completed","item":{"id":"i1","type":"agent_message","text":"{\"action\":\"idle\"}"}}
{"type":"item.completed","item":{"id":"i2","type":"agent_message","text":"{\"action\":\"needs_email\"}"}}"#;

        let message = extract_last_agent_message(stream).expect("agent message should exist");
        assert_eq!(message, r#"{"action":"needs_email"}"#);
    }
}
