use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeEntry {
    pub path: PathBuf,
    pub branch_ref: Option<String>,
}

pub fn ensure_repo(project_root: &Path) -> Result<()> {
    let output = run_git(project_root, ["rev-parse", "--is-inside-work-tree"])?;
    if !output.status.success() {
        bail!(
            "not a git repository: {}\n{}",
            project_root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

pub fn current_branch(project_root: &Path) -> Result<String> {
    let output = run_git(project_root, ["branch", "--show-current"])?;
    if !output.status.success() {
        bail!(
            "failed to resolve current branch: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn branch_exists(project_root: &Path, branch: &str) -> Result<bool> {
    let output = run_git(
        project_root,
        [
            "show-ref",
            "--verify",
            "--quiet",
            &format!("refs/heads/{branch}"),
        ],
    )?;
    Ok(output.status.success())
}

pub fn checkout(project_root: &Path, branch: &str) -> Result<()> {
    let output = run_git(project_root, ["checkout", branch])?;
    if !output.status.success() {
        bail!(
            "git checkout {branch} failed:\n{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

pub fn create_branch(project_root: &Path, branch: &str, from_branch: Option<&str>) -> Result<()> {
    let mut command = Command::new("git");
    command
        .current_dir(project_root)
        .arg("checkout")
        .arg("-b")
        .arg(branch);
    if let Some(base) = from_branch {
        command.arg(base);
    }

    let output = command
        .output()
        .context("failed to execute git checkout -b")?;
    if !output.status.success() {
        bail!(
            "git checkout -b {branch} failed:\n{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(())
}

pub fn worktree_for_branch(project_root: &Path, branch: &str) -> Result<Option<PathBuf>> {
    let expected_ref = format!("refs/heads/{branch}");
    for entry in list_worktrees(project_root)? {
        if entry.branch_ref.as_deref() == Some(expected_ref.as_str()) {
            let path = if entry.path.is_absolute() {
                entry.path
            } else {
                project_root.join(entry.path)
            };
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn list_worktrees(project_root: &Path) -> Result<Vec<WorktreeEntry>> {
    let output = run_git(project_root, ["worktree", "list", "--porcelain"])?;
    if !output.status.success() {
        bail!(
            "failed to list git worktrees:\n{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(parse_worktree_list(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn parse_worktree_list(raw: &str) -> Vec<WorktreeEntry> {
    let mut entries = Vec::new();
    let mut current_path: Option<PathBuf> = None;
    let mut current_branch_ref: Option<String> = None;

    let flush = |entries: &mut Vec<WorktreeEntry>,
                 current_path: &mut Option<PathBuf>,
                 current_branch_ref: &mut Option<String>| {
        if let Some(path) = current_path.take() {
            entries.push(WorktreeEntry {
                path,
                branch_ref: current_branch_ref.take(),
            });
        } else {
            current_branch_ref.take();
        }
    };

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            flush(&mut entries, &mut current_path, &mut current_branch_ref);
            continue;
        }

        if let Some(path) = line.strip_prefix("worktree ") {
            flush(&mut entries, &mut current_path, &mut current_branch_ref);
            current_path = Some(PathBuf::from(path));
            continue;
        }

        if let Some(branch_ref) = line.strip_prefix("branch ") {
            current_branch_ref = Some(branch_ref.to_string());
        }
    }

    flush(&mut entries, &mut current_path, &mut current_branch_ref);
    entries
}

fn run_git<const N: usize>(project_root: &Path, args: [&str; N]) -> Result<std::process::Output> {
    Command::new("git")
        .args(args)
        .current_dir(project_root)
        .output()
        .with_context(|| format!("failed to execute git in {}", project_root.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_worktree_porcelain_output() {
        let raw = r#"worktree /repo/main
HEAD 1111111
branch refs/heads/main

worktree /repo/wt/feature-x
HEAD 2222222
branch refs/heads/feature/x
"#;

        let parsed = parse_worktree_list(raw);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].path, PathBuf::from("/repo/main"));
        assert_eq!(parsed[0].branch_ref.as_deref(), Some("refs/heads/main"));
        assert_eq!(parsed[1].path, PathBuf::from("/repo/wt/feature-x"));
        assert_eq!(
            parsed[1].branch_ref.as_deref(),
            Some("refs/heads/feature/x")
        );
    }

    #[test]
    fn parses_detached_worktree_without_branch_line() {
        let raw = r#"worktree /repo/main
HEAD 1111111
detached
"#;
        let parsed = parse_worktree_list(raw);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].path, PathBuf::from("/repo/main"));
        assert_eq!(parsed[0].branch_ref, None);
    }
}
