use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::git;

#[derive(Debug, Clone)]
pub struct PreflightOptions {
    pub project_root: PathBuf,
    pub input_files: Vec<PathBuf>,
    pub source_branch: Option<String>,
    pub julietscript_manifest: Option<PathBuf>,
    pub lint_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct PreflightReport {
    pub current_branch: String,
    pub source_branch: String,
    pub source_branch_exists: bool,
}

pub fn run_preflight(options: &PreflightOptions) -> Result<PreflightReport> {
    let project_root = options
        .project_root
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", options.project_root.display()))?;

    if !project_root.is_dir() {
        bail!(
            "project root is not a directory: {}",
            project_root.display()
        );
    }

    for path in &options.input_files {
        let resolved = resolve_against(&project_root, path);
        if !resolved.exists() {
            bail!("input file does not exist: {}", resolved.display());
        }
        if !resolved.is_file() {
            bail!("input path is not a file: {}", resolved.display());
        }
        fs::File::open(&resolved)
            .with_context(|| format!("input file is not readable: {}", resolved.display()))?;
    }

    if options.lint_enabled && !linter_available_on_path() {
        let manifest = options
            .julietscript_manifest
            .as_ref()
            .map(|path| resolve_against(&project_root, path))
            .unwrap_or_else(|| project_root.join("../julietscript/Cargo.toml"));
        if !manifest.is_file() {
            bail!(
                "julietscript-lint is not available on PATH and manifest fallback was not found: {}",
                manifest.display()
            );
        }
    }

    git::ensure_repo(&project_root)?;
    let current_branch = git::current_branch(&project_root)?;
    if current_branch.is_empty() {
        bail!(
            "repository is in detached HEAD state; branch-aware orchestration requires a named branch"
        );
    }

    let source_branch = options
        .source_branch
        .clone()
        .unwrap_or_else(|| current_branch.clone());
    let source_branch_exists = git::branch_exists(&project_root, &source_branch)?;

    Ok(PreflightReport {
        current_branch,
        source_branch,
        source_branch_exists,
    })
}

pub fn load_input_context(
    project_root: &Path,
    input_files: &[PathBuf],
    max_bytes_per_file: usize,
) -> Result<String> {
    if input_files.is_empty() {
        return Ok("(no input files provided)".to_string());
    }

    let mut sections = Vec::with_capacity(input_files.len());
    for path in input_files {
        let resolved = resolve_against(project_root, path);
        let raw = fs::read(&resolved)
            .with_context(|| format!("failed reading input file {}", resolved.display()))?;
        let original_len = raw.len();
        let trimmed = if raw.len() > max_bytes_per_file {
            raw[..max_bytes_per_file].to_vec()
        } else {
            raw
        };
        let mut snippet = String::from_utf8_lossy(&trimmed).to_string();
        if original_len > max_bytes_per_file {
            snippet.push_str(&format!(
                "\n\n[truncated: showing first {} bytes of {}]",
                max_bytes_per_file, original_len
            ));
        }

        sections.push(format!(
            "File: {}\n```text\n{}\n```",
            resolved.display(),
            snippet.trim_end()
        ));
    }

    Ok(sections.join("\n\n"))
}

fn resolve_against(base: &Path, candidate: &Path) -> PathBuf {
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    }
}

fn linter_available_on_path() -> bool {
    Command::new("julietscript-lint")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
