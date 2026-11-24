mod ast_rules;
mod chaos;
mod config;
mod gate;
mod license;
mod mcp;
mod resilience;
mod sarif;
mod sync;

use clap::{Parser, Subcommand, ValueEnum};
use config::GuardrailsConfig;
use sarif::{Finding, Severity};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

/// Replace with your Ed25519 public key bytes in production.
const EMBEDDED_LICENSE_PUBKEY: [u8; 32] = [148, 52, 200, 87, 73, 151, 57, 210, 113, 139, 56, 134, 194, 163, 112, 11, 168, 218, 73, 110, 238, 109, 41, 194, 180, 246, 161, 28, 144, 172, 91, 250];

#[derive(Parser)]
#[command(name = "guardrails", version, about = "Deterministic AI & CI Guardrail Binary")]
struct Cli {
    /// Target workspace directory
    #[arg(short, long, global = true, default_value = ".")]
    workspace: PathBuf,

    /// Path to guardrails.toml (defaults to <workspace>/guardrails.toml)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Offline Ed25519 license key (or set GUARDRAILS_LICENSE_KEY)
    #[arg(long, global = true, env = "GUARDRAILS_LICENSE_KEY")]
    license_key: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Json,
    Sarif,
}

#[derive(Clone, ValueEnum)]
enum ChaosMode {
    Http,
    Tcp,
}

#[derive(Subcommand)]
enum Commands {
    /// Create guardrails.toml and sync AGENTS.md + .mcp.json
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Sync AGENTS.md and .mcp.json from guardrails.toml
    Sync,
    /// Run embedded AST rules and unified lint/type gate
    Check {
        #[arg(long, value_enum, default_value = "json")]
        format: OutputFormat,
        /// Skip external clippy/tsc/ruff/mypy gate and run AST rules only
        #[arg(long)]
        ast_only: bool,
    },
    /// Start standalone seeded TCP/HTTP chaos proxy
    Chaos {
        #[arg(long, default_value = "127.0.0.1:9000")]
        listen: SocketAddr,
        #[arg(long)]
        upstream: Option<String>,
        #[arg(long)]
        seed: Option<u64>,
        #[arg(long, value_enum, default_value = "http")]
        mode: ChaosMode,
    },
    /// Run Schemathesis & Keploy through the seeded chaos proxy (commercial feature)
    Resilience {
        #[arg(long)]
        seed: Option<u64>,
        #[arg(long)]
        openapi: Option<String>,
    },
    /// Start MCP JSON-RPC 2.0 server over stdio (Cursor / Claude Code / Codex)
    Mcp,
    /// Verify an offline Ed25519 license key
    LicenseCheck,
}

#[tokio::main]
async fn main() -> ExitCode {
    // Always write logs to stderr so `mcp` stdio JSON-RPC stays clean
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let workspace = cli.workspace.canonicalize().unwrap_or(cli.workspace);
    let cfg = GuardrailsConfig::load(&workspace, cli.config.as_deref())?;

    match cli.command {
        Commands::Init { force } => {
            let cfg_path = workspace.join("guardrails.toml");
            if cfg_path.exists() && !force {
                anyhow::bail!("{} already exists (pass --force to overwrite)", cfg_path.display());
            }
            let name = workspace
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("app");
            std::fs::write(&cfg_path, config::default_toml_template(name))?;
            sync::sync_all(&workspace, cfg.sync.mcp_json, cfg.sync.agents_md)?;
            eprintln!("Initialized {} and synced agent configs.", cfg_path.display());
            Ok(ExitCode::SUCCESS)
        }

        Commands::Sync => {
            sync::sync_all(&workspace, cfg.sync.mcp_json, cfg.sync.agents_md)?;
            eprintln!("Synced .mcp.json and AGENTS.md.");
            Ok(ExitCode::SUCCESS)
        }

        Commands::Check { format, ast_only } => {
            let mut findings: Vec<Finding> = Vec::new();

            if cfg.ast.enabled {
                findings.extend(ast_rules::scan_workspace(&workspace, &cfg.ast.exclude)?);
            }
            if !ast_only {
                findings.extend(gate::run_unified_gate(&workspace, &cfg.gate).await?);
            }

            // Deduplicate identical diagnostics (e.g. clippy bin + test passes)
            let mut seen = std::collections::HashSet::new();
            findings.retain(|f| {
                seen.insert((
                    f.rule_id.clone(),
                    f.file.clone(),
                    f.start_line,
                    f.start_col,
                    f.message.clone(),
                ))
            });

            let out = match format {
                OutputFormat::Json => serde_json::to_string_pretty(&findings)?,
                OutputFormat::Sarif => serde_json::to_string_pretty(&sarif::to_sarif(&findings))?,
            };
            println!("{out}");

            let should_fail = findings.iter().any(|f| match cfg.project.fail_on.as_str() {
                "warning" => matches!(f.severity, Severity::Error | Severity::Warning),
                _ => matches!(f.severity, Severity::Error),
            });

            Ok(if should_fail {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }

        Commands::Chaos { listen, upstream, seed, mode } => {
            let chaos_cfg = chaos::ChaosConfig {
                seed: seed.unwrap_or(cfg.resilience.seed),
                drop_rate: cfg.resilience.drop_rate,
                rate_429: cfg.resilience.rate_429,
                max_jitter_ms: cfg.resilience.max_jitter_ms,
                upstream: upstream.unwrap_or(cfg.resilience.upstream),
            };
            match mode {
                ChaosMode::Http => {
                    eprintln!("HTTP chaos proxy listening on http://{listen} (seed={})", chaos_cfg.seed);
                    chaos::start_http_chaos_proxy(listen, chaos_cfg).await?;
                }
                ChaosMode::Tcp => {
                    eprintln!("TCP/WS chaos proxy listening on {listen} (seed={})", chaos_cfg.seed);
                    chaos::start_tcp_chaos_proxy(listen, chaos_cfg).await?;
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        Commands::Resilience { seed, openapi } => {
            require_commercial_license(cli.license_key.as_deref())?;
            let opts = resilience::ResilienceOptions {
                upstream: cfg.resilience.upstream,
                seed: seed.unwrap_or(cfg.resilience.seed),
                drop_rate: cfg.resilience.drop_rate,
                rate_429: cfg.resilience.rate_429,
                max_jitter_ms: cfg.resilience.max_jitter_ms,
                openapi_spec: openapi.or(cfg.resilience.openapi_spec),
                keploy_cmd: cfg.resilience.keploy_cmd,
            };
            resilience::run_resilience_suite(&workspace, opts).await?;
            Ok(ExitCode::SUCCESS)
        }

        Commands::Mcp => {
            mcp::run_mcp_stdio(workspace).await?;
            Ok(ExitCode::SUCCESS)
        }

        Commands::LicenseCheck => {
            let key = cli
                .license_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("Provide --license-key or GUARDRAILS_LICENSE_KEY"))?;
            let claims = license::verify_license(key, &EMBEDDED_LICENSE_PUBKEY, now_unix())?;
            println!(
                "Valid license: org={}, tier={}, expires_unix={}",
                claims.org, claims.tier, claims.expires_unix
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn require_commercial_license(key: Option<&str>) -> anyhow::Result<()> {
    let key = key.ok_or_else(|| {
        anyhow::anyhow!("Commercial license required: pass --license-key or set GUARDRAILS_LICENSE_KEY")
    })?;
    let claims = license::verify_license(key, &EMBEDDED_LICENSE_PUBKEY, now_unix())?;
    if claims.tier == "free" {
        anyhow::bail!("Tier '{}' does not include resilience suite", claims.tier);
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}