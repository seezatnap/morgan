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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultsGuidance {
    pub winning_branch: Option<String>,
    pub work_remaining: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ResultsGuidanceEnvelope {
    #[serde(default)]
    winning_branch: Option<String>,
    #[serde(default)]
    work_remaining: Option<bool>,
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

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        bail!(
            "`codex login status` failed (exit {}):\n{}",
            output.status.code().unwrap_or(1),
            combine_status_output(&stdout, &stderr)
        );
    }

    ensure_login_status_ready(&stdout, &stderr)
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

pub fn infer_results_guidance(cwd: &Path, juliet_output: &str) -> Result<ResultsGuidance> {
    let prompt = build_results_guidance_prompt(juliet_output);
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
            "`codex exec` results guidance failed (exit {}):\n{}",
            output.status.code().unwrap_or(1),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let agent_message = extract_last_agent_message(&output.stdout)
        .context("results guidance did not return an agent_message result")?;
    parse_results_guidance_from_message(&agent_message)
}

fn build_classifier_prompt(juliet_output: &str) -> String {
    format!(
        "Classify the most appropriate next action from JULIET_OUTPUT only.\nReturn ONLY compact JSON with shape {{\"action\":\"<label>\"}}.\nAllowed labels: needs_email, needs_task_review, still_working, results_review, results_complete, branch_clarification, idle, unknown.\n\nJULIET_OUTPUT:\n{}",
        juliet_output
    )
}

fn build_results_guidance_prompt(juliet_output: &str) -> String {
    format!(
        "Extract result-routing hints from JULIET_OUTPUT only.\nReturn ONLY compact JSON with shape {{\"winning_branch\":<string|null>,\"work_remaining\":<true|false|null>}}.\nRules:\n- winning_branch: provide the winning git branch when explicit or strongly implied; otherwise null.\n- work_remaining: true when more sprint work remains, false when the work appears complete, null when unclear.\n- Do not include extra keys.\n\nJULIET_OUTPUT:\n{}",
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

fn parse_results_guidance_from_message(message: &str) -> Result<ResultsGuidance> {
    if let Ok(envelope) = serde_json::from_str::<ResultsGuidanceEnvelope>(message) {
        return normalize_results_guidance(envelope);
    }

    let object_re = Regex::new(r#"\{[\s\S]*\}"#).unwrap();
    if let Some(found) = object_re.find(message) {
        let snippet = found.as_str();
        if let Ok(envelope) = serde_json::from_str::<ResultsGuidanceEnvelope>(snippet) {
            return normalize_results_guidance(envelope);
        }
    }

    bail!(
        "unable to parse results guidance JSON from message: {}",
        message
    )
}

fn normalize_results_guidance(envelope: ResultsGuidanceEnvelope) -> Result<ResultsGuidance> {
    let branch_re = Regex::new(r#"^[A-Za-z0-9._/\-]+$"#).unwrap();
    let winning_branch = envelope
        .winning_branch
        .map(|branch| branch.trim().trim_matches('`').to_string())
        .filter(|branch| !branch.is_empty());

    if let Some(branch) = winning_branch.as_deref()
        && !branch_re.is_match(branch)
    {
        bail!("invalid winning_branch '{}' from guidance", branch);
    }

    Ok(ResultsGuidance {
        winning_branch,
        work_remaining: envelope.work_remaining,
    })
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

fn combine_status_output(stdout: &str, stderr: &str) -> String {
    let stdout = stdout.trim();
    let stderr = stderr.trim();
    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => "(no output)".to_string(),
        (false, true) => stdout.to_string(),
        (true, false) => stderr.to_string(),
        (false, false) => format!("stdout:\n{stdout}\n\nstderr:\n{stderr}"),
    }
}

fn ensure_login_status_ready(stdout: &str, stderr: &str) -> Result<()> {
    let combined = combine_status_output(stdout, stderr);
    if combined == "(no output)" {
        // Treat successful but silent output as ready so CLI phrasing changes
        // do not block orchestration.
        return Ok(());
    }

    let lower = combined.to_ascii_lowercase();
    if login_status_indicates_not_ready(&lower) {
        bail!(
            "Codex is not ready. `codex login status` indicates no active login:\n{}",
            combined
        );
    }

    // If login status succeeds and does not explicitly indicate a missing login,
    // accept it as ready to avoid brittle coupling to exact wording.
    Ok(())
}

fn login_status_indicates_not_ready(lower: &str) -> bool {
    [
        "not logged in",
        "no active login",
        "run codex login",
        "run `codex login`",
        "please log in",
        "please login",
        "sign in",
        "not authenticated",
        "authentication required",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
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
    fn parses_results_guidance_json() {
        let guidance = parse_results_guidance_from_message(
            r#"{"winning_branch":"feature/foo-try2","work_remaining":true}"#,
        )
        .expect("should parse guidance");
        assert_eq!(
            guidance,
            ResultsGuidance {
                winning_branch: Some("feature/foo-try2".to_string()),
                work_remaining: Some(true),
            }
        );
    }

    #[test]
    fn parses_embedded_results_guidance_json() {
        let guidance = parse_results_guidance_from_message(
            "Winner summary:\n{\"winning_branch\":\"feature/foo\",\"work_remaining\":false}",
        )
        .expect("should parse embedded guidance");
        assert_eq!(
            guidance,
            ResultsGuidance {
                winning_branch: Some("feature/foo".to_string()),
                work_remaining: Some(false),
            }
        );
    }

    #[test]
    fn extracts_last_agent_message_from_codex_stream() {
        let stream = br#"{"type":"thread.started","thread_id":"t1"}
{"type":"item.completed","item":{"id":"i1","type":"agent_message","text":"{\"action\":\"idle\"}"}}
{"type":"item.completed","item":{"id":"i2","type":"agent_message","text":"{\"action\":\"needs_email\"}"}}"#;

        let message = extract_last_agent_message(stream).expect("agent message should exist");
        assert_eq!(message, r#"{"action":"needs_email"}"#);
    }

    #[test]
    fn readiness_accepts_empty_success_output() {
        assert!(ensure_login_status_ready("", "").is_ok());
    }

    #[test]
    fn readiness_accepts_logged_in_output() {
        assert!(ensure_login_status_ready("Logged in using API key", "").is_ok());
    }

    #[test]
    fn readiness_rejects_not_logged_in_output() {
        let err = ensure_login_status_ready("Not logged in. Run codex login.", "")
            .expect_err("should reject missing login");
        assert!(err.to_string().contains("indicates no active login"));
    }
}
