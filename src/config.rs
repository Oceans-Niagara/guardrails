use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    #[default]
    General,
    Fintech,
    Frontend,
    WebApi,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::General => "general",
            Profile::Fintech => "fintech",
            Profile::Frontend => "frontend",
            Profile::WebApi => "web-api",
        }
    }

    pub fn default_disabled_rules(self) -> Vec<&'static str> {
        match self {
            Profile::General | Profile::Frontend => vec!["GR001", "GR003"],
            Profile::WebApi => vec!["GR001"],
            Profile::Fintech => vec![],
        }
    }
}

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
    pub profile: Profile,
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
            profile: Profile::General,
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

#[derive(Debug, Clone)]
pub struct DetectedWorkspace {
    pub profile: Profile,
    pub gate: GateConfig,
    pub openapi_spec: Option<String>,
}

pub fn detect_workspace(workspace: &Path) -> DetectedWorkspace {
    let mut has_rust = false;
    let mut has_ts = false;
    let mut has_tsx = false;
    let mut has_py = false;
    let mut openapi_spec: Option<String> = None;
    let mut manifest_corpus = String::new();
    let mut file_names_corpus = String::new();

    if let Some(name) = workspace.file_name().and_then(|n| n.to_str()) {
        file_names_corpus.push_str(&name.to_ascii_lowercase());
        file_names_corpus.push('\n');
    }

    for entry in WalkBuilder::new(workspace)
        .max_depth(Some(3))
        .hidden(true)
        .git_ignore(true)
        .build()
        .flatten()
    {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();
        let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let lower_name = fname.to_ascii_lowercase();
        file_names_corpus.push_str(&lower_name);
        file_names_corpus.push('\n');

        match lower_name.as_str() {
            "cargo.toml" => has_rust = true,
            "tsconfig.json" => has_ts = true,
            "pyproject.toml" | "requirements.txt" | "setup.py" => has_py = true,
            "openapi.yaml" | "openapi.yml" | "openapi.json" if openapi_spec.is_none() => {
                openapi_spec = path
                    .strip_prefix(workspace)
                    .ok()
                    .map(|p| p.to_string_lossy().replace('\\', "/"));
            }
            _ => {}
        }

        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            match ext {
                "rs" => has_rust = true,
                "ts" => has_ts = true,
                "tsx" => {
                    has_ts = true;
                    has_tsx = true;
                }
                "py" => has_py = true,
                _ => {}
            }
        }

        if matches!(
            lower_name.as_str(),
            "cargo.toml" | "package.json" | "pyproject.toml" | "requirements.txt" | "setup.py"
        ) {
            if let Ok(raw) = fs::read_to_string(path) {
                let lower_raw = raw.to_ascii_lowercase();
                if lower_name == "package.json" && lower_raw.contains("typescript") {
                    has_ts = true;
                }
                manifest_corpus.push_str(&lower_raw);
                manifest_corpus.push('\n');
            }
        }
    }

    let gate = if !has_rust && !has_ts && !has_py {
        GateConfig::default()
    } else {
        GateConfig {
            rust: has_rust,
            typescript: has_ts,
            python: has_py,
        }
    };

    let fintech_signals = [
        "stripe",
        "paypal",
        "adyen",
        "braintree",
        "plaid",
        "rust_decimal",
        "decimal.js",
        "big.js",
        "billing",
        "invoice",
        "ledger",
        "payment",
        "checkout",
    ];
    let web_api_signals = [
        "axum",
        "actix-web",
        "rocket",
        "tonic",
        "express",
        "fastify",
        "hono",
        "@nestjs/",
        "koa",
        "fastapi",
        "flask",
        "django",
        "starlette",
        "uvicorn",
        "aiohttp",
    ];
    let frontend_signals = [
        "\"react\"",
        "\"next\"",
        "\"vite\"",
        "\"vue\"",
        "\"svelte\"",
        "\"@angular/core\"",
        "\"astro\"",
        "\"solid-js\"",
    ];

    let combined = format!("{manifest_corpus}\n{file_names_corpus}");
    let profile = if fintech_signals.iter().any(|kw| combined.contains(kw)) {
        Profile::Fintech
    } else if openapi_spec.is_some() || web_api_signals.iter().any(|kw| manifest_corpus.contains(kw))
    {
        Profile::WebApi
    } else if !gate.rust
        && !gate.python
        && (has_tsx || frontend_signals.iter().any(|kw| manifest_corpus.contains(kw)))
    {
        Profile::Frontend
    } else {
        Profile::General
    };

    DetectedWorkspace {
        profile,
        gate,
        openapi_spec,
    }
}

pub fn render_toml_for_init(
    project_name: &str,
    detected: &DetectedWorkspace,
    profile_override: Option<Profile>,
) -> String {
    let profile = profile_override.unwrap_or(detected.profile);
    let disabled = profile.default_disabled_rules();
    let rules_line = if disabled.is_empty() {
        "# disabled = [\"GR001\", \"GR003\"]".to_string()
    } else {
        let joined = disabled
            .iter()
            .map(|r| format!("\"{r}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!("disabled = [{joined}]")
    };
    let openapi_line = match &detected.openapi_spec {
        Some(spec) => format!("openapi_spec = \"{spec}\""),
        None => "# openapi_spec = \"openapi.yaml\"".to_string(),
    };

    format!(
        r#"[project]
name = "{project_name}"
profile = "{}" # "general" | "fintech" | "frontend" | "web-api"
fail_on = "error" # "error" | "warning"

[ast]
enabled = true
exclude = ["target/**", "node_modules/**", ".venv/**"]

[gate]
rust = {}
typescript = {}
python = {}

[rules]
{rules_line}

[agents]
# Append optional project-specific instructions to AGENTS.md:
# custom_rules = ["Validate all CLI flags and exit non-zero on invalid input."]

[resilience]
upstream = "127.0.0.1:8080"
seed = 42
drop_rate = 0.02
rate_429 = 0.05
max_jitter_ms = 150
{openapi_line}
# keploy_cmd = "node dist/server.js"

[sync]
agents_md = true
mcp_json = true
"#,
        profile.as_str(),
        detected.gate.rust,
        detected.gate.typescript,
        detected.gate.python,
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

    #[test]
    fn detects_general_fintech_frontend_and_web_api_profiles() {
        let base = std::env::temp_dir().join(format!("guardrails_detect_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);

        // 1. General TS CLI/astrology app
        let astro = base.join("astrology-app");
        fs::create_dir_all(&astro).unwrap();
        fs::write(astro.join("package.json"), r#"{"name":"astrology","dependencies":{"typescript":"^5"}}"#).unwrap();
        fs::write(astro.join("chart.ts"), "export const sign = 'Aries';\n").unwrap();
        let d_astro = detect_workspace(&astro);
        assert_eq!(d_astro.profile, Profile::General);
        assert!(!d_astro.gate.rust && d_astro.gate.typescript && !d_astro.gate.python);

        // 2. Frontend React app
        let ui = base.join("zodiac-ui");
        fs::create_dir_all(&ui).unwrap();
        fs::write(ui.join("package.json"), r#"{"dependencies":{"react":"^19","vite":"^6"}}"#).unwrap();
        fs::write(ui.join("App.tsx"), "export function App() { return <main />; }\n").unwrap();
        let d_ui = detect_workspace(&ui);
        assert_eq!(d_ui.profile, Profile::Frontend);
        assert!(!d_ui.gate.rust && d_ui.gate.typescript && !d_ui.gate.python);

        // 3. Web API (Python FastAPI)
        let api = base.join("horoscope-api");
        fs::create_dir_all(&api).unwrap();
        fs::write(api.join("requirements.txt"), "fastapi==0.115.0\nuvicorn\n").unwrap();
        let d_api = detect_workspace(&api);
        assert_eq!(d_api.profile, Profile::WebApi);
        assert!(!d_api.gate.rust && !d_api.gate.typescript && d_api.gate.python);

        // 4. Fintech (Stripe)
        let pay = base.join("billing-service");
        fs::create_dir_all(&pay).unwrap();
        fs::write(pay.join("Cargo.toml"), "[dependencies]\nstripe = \"0.20\"\n").unwrap();
        let d_pay = detect_workspace(&pay);
        assert_eq!(d_pay.profile, Profile::Fintech);
        assert!(d_pay.gate.rust && !d_pay.gate.typescript && !d_pay.gate.python);

        let _ = fs::remove_dir_all(&base);
    }
}