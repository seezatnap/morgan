use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::engine::Engine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptSpec {
    pub artifact_name: String,
    pub master_prompt: String,
    pub input_context: String,
    pub engine: Engine,
    pub variants: u32,
    pub sprints: u32,
    pub keep_best: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub artifact_name: String,
    pub engine: Engine,
    pub variants: u32,
    pub sprints: u32,
    pub keep_best: u32,
    pub create_prompt: String,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct CadenceConfig {
    engine: Engine,
    variants: u32,
    sprints: u32,
    keep_best: u32,
}

pub fn validate_artifact_name(artifact_name: &str) -> Result<()> {
    let re = Regex::new(r#"^[A-Za-z][A-Za-z0-9_]*$"#).unwrap();
    if re.is_match(artifact_name) {
        return Ok(());
    }
    bail!(
        "invalid artifact name '{}': use [A-Za-z][A-Za-z0-9_]* (letters, digits, underscore; must start with a letter)",
        artifact_name
    );
}

pub fn generate_script(spec: &ScriptSpec) -> String {
    let create_prompt = format!(
        "Master prompt:\\n{}\\n\\nInput context:\\n{}\\n\\nOperational requirements:\\n- Run preflight checks before sprint launches.\\n- Ask for review when a human decision is required.\\n- If branches drift or mismatch, stop and ask for branch clarification before continuing.\\n- Grade sprint results using the rubric before selecting winners.",
        spec.master_prompt.trim(),
        spec.input_context.trim()
    );

    format!(
        r#"juliet {{
  engine = {engine};
}}

policy Preflight = """
Before sprinting:
- verify source/target branch intent and current git branch alignment
- verify required project artifacts and run inputs are present
- verify run parameters are explicit and valid
Return pass/fail checks and required operator actions.
""";

policy FailureTriage = """
If a run fails:
- capture failing command, short error, and probable root cause
- attempt one safe recovery
- if recovery fails, request human review with branch + log context
""";

rubric DeliveryRubric {{
  criterion "Correctness" points 5 means "Implements requested behavior with no obvious regressions.";
  criterion "Safety" points 3 means "Handles branch/process failures safely and reports uncertainty.";
  criterion "Traceability" points 2 means "Decisions and outputs are inspectable with clear context.";
  tiebreakers ["Correctness", "Safety"];
}}

cadence DeliveryCadence {{
  engine = {engine};
  variants = {variants};
  sprints = {sprints};
  compare using DeliveryRubric;
  keep best {keep_best};
}}

create {artifact_name} from juliet """
{create_prompt}
"""
with {{
  preflight = Preflight;
  failureTriage = FailureTriage;
  cadence = DeliveryCadence;
  rubric = DeliveryRubric;
}};
"#,
        engine = spec.engine,
        variants = spec.variants.max(1),
        sprints = spec.sprints.max(1),
        keep_best = spec.keep_best.max(1),
        artifact_name = spec.artifact_name,
        create_prompt = escape_block_string(&create_prompt),
    )
}

pub fn parse_execution_plan(script: &str) -> Result<ExecutionPlan> {
    let mut plans = parse_execution_plans(script)?;
    plans
        .drain(..1)
        .next()
        .context("julietscript does not include any create statements")
}

pub fn parse_execution_plans(script: &str) -> Result<Vec<ExecutionPlan>> {
    let cadence_block_re =
        Regex::new(r#"(?ms)^\s*cadence\s+(?P<name>[A-Za-z][A-Za-z0-9_]*)\s*\{(?P<body>.*?)\}"#)
            .unwrap();
    let create_re = Regex::new(
        r#"(?ms)^\s*create\s+(?P<artifact>[A-Za-z][A-Za-z0-9_]*)\s+from\s+juliet\s+(?P<prompt>"""[\s\S]*?"""|"(?:\\.|[^"])*")(?:\s+using\s*\[(?P<using>[^\]]*)\])?\s+with\s*\{(?P<with_body>.*?)\}\s*;"#,
    )
    .unwrap();
    let juliet_block_re = Regex::new(r#"(?ms)^\s*juliet\s*\{(?P<body>.*?)\}"#).unwrap();
    let cadence_ref_re =
        Regex::new(r#"(?m)\bcadence\s*=\s*(?P<name>[A-Za-z][A-Za-z0-9_]*)\s*;"#).unwrap();
    let masked_script = mask_string_literals(script);

    let default_engine = juliet_block_re
        .captures(&masked_script)
        .and_then(|caps| caps.name("body").map(|body| body.as_str()))
        .and_then(capture_engine);

    let mut cadence_configs = HashMap::new();
    let mut first_cadence_name: Option<String> = None;
    for cadence_caps in cadence_block_re.captures_iter(&masked_script) {
        let cadence_name = cadence_caps
            .name("name")
            .map(|m| m.as_str())
            .context("missing cadence name in julietscript")?;
        let cadence_body = cadence_caps
            .name("body")
            .map(|m| m.as_str())
            .context("missing cadence body in julietscript")?;
        let engine = capture_engine(cadence_body)
            .or(default_engine)
            .with_context(|| format!("unable to resolve engine for cadence '{}'", cadence_name))?;
        let config = CadenceConfig {
            engine,
            variants: capture_u32(cadence_body, "variants").unwrap_or(1),
            sprints: capture_u32(cadence_body, "sprints").unwrap_or(1),
            keep_best: capture_keep_best(cadence_body).unwrap_or(1),
        };
        if cadence_configs
            .insert(cadence_name.to_string(), config)
            .is_some()
        {
            bail!("duplicate cadence '{}' in julietscript", cadence_name);
        }
        if first_cadence_name.is_none() {
            first_cadence_name = Some(cadence_name.to_string());
        }
    }
    if cadence_configs.is_empty() {
        bail!("missing cadence block in julietscript");
    }

    let mut plans = Vec::new();
    for create_caps in create_re.captures_iter(script) {
        let artifact_name = create_caps
            .name("artifact")
            .map(|m| m.as_str().to_string())
            .context("missing artifact name in create statement")?;

        let create_prompt_raw = create_caps
            .name("prompt")
            .map(|m| m.as_str())
            .context("missing create prompt in create statement")?;

        let create_prompt = decode_string_literal(create_prompt_raw).with_context(|| {
            format!("failed to parse create prompt literal: {create_prompt_raw}")
        })?;

        let with_body = create_caps
            .name("with_body")
            .map(|m| m.as_str())
            .context("missing with block in create statement")?;
        let cadence_name = cadence_ref_re
            .captures(with_body)
            .and_then(|caps| caps.name("name").map(|m| m.as_str().to_string()));
        let cadence = if let Some(name) = cadence_name {
            *cadence_configs.get(&name).with_context(|| {
                format!(
                    "create '{}' references cadence '{}' which is not defined",
                    artifact_name, name
                )
            })?
        } else if cadence_configs.len() == 1 {
            let first = first_cadence_name
                .as_ref()
                .context("internal error: cadence list unexpectedly empty")?;
            *cadence_configs
                .get(first)
                .context("internal error: first cadence missing from config map")?
        } else {
            bail!(
                "create '{}' is missing `cadence = <name>;` in its with block while multiple cadences are defined",
                artifact_name
            );
        };

        let dependencies = parse_dependencies(create_caps.name("using").map(|m| m.as_str()));

        plans.push(ExecutionPlan {
            artifact_name,
            engine: cadence.engine,
            variants: cadence.variants,
            sprints: cadence.sprints,
            keep_best: cadence.keep_best,
            create_prompt,
            dependencies,
        });
    }

    if plans.is_empty() {
        bail!("missing create statement in julietscript");
    }

    Ok(plans)
}

pub fn lint_script(script_path: &Path, julietscript_manifest_path: &Path) -> Result<()> {
    let script_path = script_path
        .canonicalize()
        .with_context(|| format!("failed to resolve script path {}", script_path.display()))?;
    let script_dir = script_path
        .parent()
        .context("script path has no parent directory")?;
    let script_name = script_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("script path is not valid UTF-8")?;

    match run_linter_from_path(script_dir, script_name) {
        Ok(output) => return interpret_lint_output(output, "julietscript-lint (PATH)"),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            bail!("failed to execute julietscript-lint from PATH: {err}");
        }
    }

    let output = run_linter_via_manifest(script_dir, script_name, julietscript_manifest_path)
        .context("failed to execute julietscript linter via Cargo manifest fallback")?;
    interpret_lint_output(output, "julietscript-lint (cargo manifest fallback)")
}

fn run_linter_from_path(script_dir: &Path, script_name: &str) -> io::Result<Output> {
    Command::new("julietscript-lint")
        .arg("--root")
        .arg(script_dir)
        .arg("--glob")
        .arg(script_name)
        .output()
}

fn run_linter_via_manifest(
    script_dir: &Path,
    script_name: &str,
    julietscript_manifest_path: &Path,
) -> io::Result<Output> {
    Command::new("cargo")
        .arg("run")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(julietscript_manifest_path)
        .arg("-p")
        .arg("julietscript-lint")
        .arg("--")
        .arg("--root")
        .arg(script_dir)
        .arg("--glob")
        .arg(script_name)
        .output()
}

fn interpret_lint_output(output: Output, source: &str) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let code = output.status.code().unwrap_or(1);

    if code == 1 {
        bail!(
            "julietscript validation failed via {}:\n{}\n{}",
            source,
            stdout.trim(),
            stderr.trim()
        );
    }

    bail!(
        "julietscript-lint exited with code {} via {}:\n{}\n{}",
        code,
        source,
        stdout.trim(),
        stderr.trim()
    );
}

fn escape_block_string(input: &str) -> String {
    input.replace(r#"""""#, r#"\"\"\""#)
}

fn decode_string_literal(literal: &str) -> Result<String> {
    if let Some(stripped) = literal
        .strip_prefix(r#""""#)
        .and_then(|rest| rest.strip_suffix(r#""""#))
    {
        return Ok(stripped.to_string());
    }

    if literal.starts_with('"') {
        let decoded: String = serde_json::from_str(literal)
            .with_context(|| format!("invalid quoted string literal: {literal}"))?;
        return Ok(decoded);
    }

    bail!("unsupported string literal format");
}

fn capture_engine(block_body: &str) -> Option<Engine> {
    let re = Regex::new(r#"\bengine\s*=\s*(?P<engine>"[^"]+"|[A-Za-z]+)\s*;"#).unwrap();
    for line in block_body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some(value) = re
            .captures(trimmed)
            .and_then(|caps| caps.name("engine").map(|m| m.as_str()))
            .and_then(Engine::parse)
        {
            return Some(value);
        }
    }
    None
}

fn capture_u32(block_body: &str, key: &str) -> Option<u32> {
    let pattern = format!(r#"\b{}\s*=\s*(?P<value>\d+)\s*;"#, regex::escape(key));
    let re = Regex::new(&pattern).ok()?;
    for line in block_body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some(value) = re
            .captures(trimmed)
            .and_then(|caps| caps.name("value"))
            .and_then(|m| m.as_str().parse::<u32>().ok())
        {
            return Some(value);
        }
    }
    None
}

fn capture_keep_best(block_body: &str) -> Option<u32> {
    let re = Regex::new(r#"\bkeep\s+best\s+(?P<value>\d+)\s*;"#).unwrap();
    for line in block_body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if let Some(value) = re
            .captures(trimmed)
            .and_then(|caps| caps.name("value"))
            .and_then(|m| m.as_str().parse::<u32>().ok())
        {
            return Some(value);
        }
    }
    None
}

fn mask_string_literals(script: &str) -> String {
    let string_re = Regex::new(r#"(?s)"""[\s\S]*?"""|"(?:\\.|[^"])*""#).unwrap();
    let mut bytes = script.as_bytes().to_vec();
    for literal in string_re.find_iter(script) {
        for byte in &mut bytes[literal.start()..literal.end()] {
            if *byte != b'\n' && *byte != b'\r' {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(bytes).expect("masked script should remain valid UTF-8")
}

fn parse_dependencies(using_block: Option<&str>) -> Vec<String> {
    let Some(raw) = using_block else {
        return Vec::new();
    };

    raw.split(',')
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_script_contains_required_blocks() {
        let spec = ScriptSpec {
            artifact_name: "ShipCLI".to_string(),
            master_prompt: "Build the release CLI.".to_string(),
            input_context: "- /tmp/spec.md".to_string(),
            engine: Engine::Codex,
            variants: 3,
            sprints: 2,
            keep_best: 1,
        };

        let script = generate_script(&spec);
        assert!(script.contains("juliet {"));
        assert!(script.contains("policy Preflight"));
        assert!(script.contains("rubric DeliveryRubric"));
        assert!(script.contains("cadence DeliveryCadence"));
        assert!(script.contains("create ShipCLI from juliet"));
    }

    #[test]
    fn parse_execution_plan_extracts_expected_values() {
        let script = r#"
juliet {
  engine = codex;
}

cadence X {
  engine = codex;
  variants = 4;
  sprints = 3;
  keep best 2;
}

create ArtifactA from juliet "Ship it"
with {
  cadence = X;
};
"#;

        let plan = parse_execution_plan(script).expect("plan should parse");
        assert_eq!(plan.artifact_name, "ArtifactA");
        assert_eq!(plan.engine, Engine::Codex);
        assert_eq!(plan.variants, 4);
        assert_eq!(plan.sprints, 3);
        assert_eq!(plan.keep_best, 2);
        assert_eq!(plan.create_prompt, "Ship it");
        assert!(plan.dependencies.is_empty());
    }

    #[test]
    fn parse_execution_plan_supports_block_string_prompt() {
        let script = r#"
juliet {
  engine = codex;
}

cadence X {
  variants = 1;
  sprints = 1;
}

create ArtifactA from juliet """
line one
line two
"""
with {
  preflight = Preflight;
  failureTriage = FailureTriage;
  cadence = X;
  rubric = DeliveryRubric;
};
"#;

        let plan = parse_execution_plan(script).expect("plan should parse block strings");
        assert!(plan.create_prompt.contains("line one"));
        assert!(plan.create_prompt.contains("line two"));
        assert!(plan.dependencies.is_empty());
    }

    #[test]
    fn parse_execution_plans_preserves_artifact_order_and_dependencies() {
        let script = r#"
juliet {
  engine = codex;
}

cadence X {
  variants = 2;
  sprints = 2;
}

create ArtifactA from juliet "build A"
with {
  cadence = X;
};

create ArtifactB from juliet "build B"
using [ArtifactA]
with {
  cadence = X;
};
"#;

        let plans = parse_execution_plans(script).expect("plans should parse");
        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0].artifact_name, "ArtifactA");
        assert_eq!(plans[0].dependencies, Vec::<String>::new());
        assert_eq!(plans[1].artifact_name, "ArtifactB");
        assert_eq!(plans[1].dependencies, vec!["ArtifactA".to_string()]);
    }

    #[test]
    fn parse_execution_plans_uses_cadence_bound_in_create_with_block() {
        let script = r#"
juliet {
  engine = codex;
}

cadence Fast {
  variants = 5;
  sprints = 1;
  keep best 3;
}

cadence Deep {
  engine = claude;
  variants = 1;
  sprints = 4;
  keep best 1;
}

create ArtifactA from juliet "build A"
with {
  cadence = Fast;
};

create ArtifactB from juliet "build B"
using [ArtifactA]
with {
  cadence = Deep;
};
"#;

        let plans = parse_execution_plans(script).expect("plans should parse");
        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0].artifact_name, "ArtifactA");
        assert_eq!(plans[0].engine, Engine::Codex);
        assert_eq!(plans[0].variants, 5);
        assert_eq!(plans[0].sprints, 1);
        assert_eq!(plans[0].keep_best, 3);
        assert_eq!(plans[1].artifact_name, "ArtifactB");
        assert_eq!(plans[1].engine, Engine::Claude);
        assert_eq!(plans[1].variants, 1);
        assert_eq!(plans[1].sprints, 4);
        assert_eq!(plans[1].keep_best, 1);
    }

    #[test]
    fn parse_execution_plans_rejects_unknown_cadence_reference() {
        let script = r#"
juliet {
  engine = codex;
}

cadence Fast {
  variants = 2;
}

create ArtifactA from juliet "build A"
with {
  cadence = MissingCadence;
};
"#;

        let err = parse_execution_plans(script).expect_err("unknown cadence should fail");
        assert!(
            err.to_string()
                .contains("references cadence 'MissingCadence'")
        );
    }

    #[test]
    fn parse_execution_plans_requires_explicit_cadence_when_multiple_defined() {
        let script = r#"
juliet {
  engine = codex;
}

cadence One {
  variants = 1;
}

cadence Two {
  variants = 2;
}

create ArtifactA from juliet "build A"
with {
  rubric = DeliveryRubric;
};
"#;

        let err = parse_execution_plans(script).expect_err("ambiguous cadence should fail");
        assert!(err.to_string().contains("missing `cadence = <name>;`"));
    }

    #[test]
    fn parse_execution_plan_ignores_cadence_text_inside_prompt() {
        let script = r#"
juliet {
  engine = codex;
}

cadence Fast {
  variants = 2;
}

create ArtifactA from juliet """
Use this snippet in docs:
cadence Fast {
  engine = claude;
}
"""
with {
  cadence = Fast;
};
"#;

        let plan = parse_execution_plan(script).expect("plan should parse");
        assert_eq!(plan.artifact_name, "ArtifactA");
        assert_eq!(plan.variants, 2);
    }

    #[test]
    fn parse_execution_plan_skips_invalid_engine_assignments_until_valid_one() {
        let script = r#"
cadence Fast {
  // engine = invalid;
  engine = codex;
}

create ArtifactA from juliet "build A"
with {
  cadence = Fast;
};
"#;

        let plan = parse_execution_plan(script).expect("plan should parse");
        assert_eq!(plan.engine, Engine::Codex);
    }

    #[test]
    fn validate_artifact_name_rejects_invalid_identifiers() {
        assert!(validate_artifact_name("Artifact_1").is_ok());
        let err = validate_artifact_name("My Artifact").expect_err("name with spaces should fail");
        assert!(err.to_string().contains("invalid artifact name"));
    }
}
