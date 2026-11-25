use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardrailsConfig {
    pub project: ProjectConfig,
    pub ast: AstConfig,
    pub gate: GateConfig,
    pub resilience: ResilienceConfig,
    pub sync: SyncConfig,
    pub rules: RulesConfig,
    pub agents: AgentsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProjectConfig {
    pub name: String,
    pub fail_on: String, // "error" | "warning"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AstConfig {
    pub enabled: bool,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GateConfig {
    pub rust: bool,
    pub typescript: bool,
    pub python: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResilienceConfig {
    pub upstream: String,
    pub seed: u64,
    pub drop_rate: f64,
    pub rate_429: f64,
    pub max_jitter_ms: u64,
    pub openapi_spec: Option<String>,
    pub keploy_cmd: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncConfig {
    pub agents_md: bool,
    pub mcp_json: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RulesConfig {
    pub disabled: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentsConfig {
    pub custom_rules: Vec<String>,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            name: "app".to_string(),
            fail_on: "error".to_string(),
        }
    }
}

impl Default for AstConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            exclude: vec![
                "target/**".to_string(),
                "node_modules/**".to_string(),
                ".venv/**".to_string(),
            ],
        }
    }
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            rust: true,
            typescript: true,
            python: true,
        }
    }
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            upstream: "127.0.0.1:8080".to_string(),
            seed: 42,
            drop_rate: 0.02,
            rate_429: 0.05,
            max_jitter_ms: 150,
            openapi_spec: None,
            keploy_cmd: None,
        }
    }
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            agents_md: true,
            mcp_json: true,
        }
    }
}

impl GuardrailsConfig {
    pub fn load(workspace: &Path, override_path: Option<&Path>) -> anyhow::Result<Self> {
        let candidate = match override_path {
            Some(p) => p.to_path_buf(),
            None => workspace.join("guardrails.toml"),
        };

        if !candidate.exists() {
            return Ok(Self::default());
        }

        let raw = fs::read_to_string(&candidate)?;
        let cfg: Self = toml::from_str(&raw)?;
        Ok(cfg)
    }

    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        let upper = rule_id.to_ascii_uppercase();
        if upper == "GR000" || upper.starts_with("GR000-") {
            return true;
        }
        !self.rules.disabled.iter().any(|entry| {
            let pat = entry.trim().to_ascii_uppercase();
            !pat.is_empty() && (upper == pat || upper.starts_with(&format!("{pat}-")))
        })
    }
}

pub fn default_toml_template(project_name: &str) -> String {
    format!(
        r#"[project]
name = "{project_name}"
fail_on = "error" # "error" | "warning"

[ast]
enabled = true
exclude = ["target/**", "node_modules/**", ".venv/**"]

[gate]
rust = true
typescript = true
python = true

[rules]
# Disable built-in rules by ID or prefix (e.g. for non-FinTech / CLI projects):
# disabled = ["GR001", "GR003"]

[agents]
# Append project-specific imperative rules to AGENTS.md:
# custom_rules = ["Validate all CLI flags and exit non-zero on invalid input."]

[resilience]
upstream = "127.0.0.1:8080"
seed = 42
drop_rate = 0.02
rate_429 = 0.05
max_jitter_ms = 150
# openapi_spec = "openapi.yaml"
# keploy_cmd = "node dist/server.js"

[sync]
agents_md = true
mcp_json = true
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_prefix_disabling_works_and_preserves_syntax_errors() {
        let mut cfg = GuardrailsConfig::default();
        cfg.rules.disabled = vec!["gr001".to_string(), "GR003-IDEMPOTENCY-TS".to_string()];

        assert!(!cfg.is_rule_enabled("GR001-FLOAT-MONEY-TS"));
        assert!(!cfg.is_rule_enabled("GR001-FLOAT-MONEY-RUST"));
        assert!(!cfg.is_rule_enabled("GR003-IDEMPOTENCY-TS"));
        assert!(cfg.is_rule_enabled("GR003-IDEMPOTENCY-PY"));
        assert!(cfg.is_rule_enabled("GR002-MISSING-TIMEOUT-TS"));
        assert!(cfg.is_rule_enabled("GR000-SYNTAX-ERROR-TS"));
    }
}