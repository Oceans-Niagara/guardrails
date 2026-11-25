use crate::config::GuardrailsConfig;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::Path;

const START_MARKER: &str = "<!-- GUARDRAILS:START -->";
const END_MARKER: &str = "<!-- GUARDRAILS:END -->";

pub fn sync_all(workspace: &Path, cfg: &GuardrailsConfig, force: bool) -> anyhow::Result<()> {
    if cfg.sync.mcp_json {
        sync_mcp_json(&workspace.join(".mcp.json"), force)?;
    }
    if cfg.sync.agents_md {
        sync_agents_md(&workspace.join("AGENTS.md"), cfg)?;
    }
    Ok(())
}

fn is_on_path(bin_name: &str) -> bool {
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };

    #[cfg(windows)]
    let candidates = [
        format!("{bin_name}.exe"),
        format!("{bin_name}.cmd"),
        bin_name.to_string(),
    ];
    #[cfg(not(windows))]
    let candidates = [bin_name.to_string()];

    std::env::split_paths(&path_var).any(|dir| {
        candidates.iter().any(|name| dir.join(name).is_file())
    })
}

pub fn resolve_mcp_command() -> String {
    if is_on_path("guardrails") {
        return "guardrails".to_string();
    }

    if let Ok(exe) = std::env::current_exe() {
        let s = exe.to_string_lossy();
        #[cfg(windows)]
        let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
        return s.to_string();
    }

    "guardrails".to_string()
}

fn sync_mcp_json(path: &Path, force: bool) -> anyhow::Result<()> {
    let mut root: Value = if path.exists() {
        let raw = fs::read_to_string(path)?;
        if raw.trim().is_empty() {
            json!({})
        } else {
            serde_json::from_str(&raw)?
        }
    } else {
        json!({})
    };

    let obj = root
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!(".mcp.json root must be a JSON object"))?;

    let servers = obj
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("`mcpServers` must be a JSON object"))?;

    let resolved_cmd = resolve_mcp_command();

    match servers.get_mut("guardrails").and_then(|v| v.as_object_mut()) {
        Some(existing) if !force => {
            let missing_cmd = existing
                .get("command")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().is_empty())
                .unwrap_or(true);
            if missing_cmd {
                existing.insert("command".to_string(), Value::String(resolved_cmd));
            }
            existing
                .entry("args")
                .or_insert_with(|| json!(["mcp", "--workspace", "."]));
        }
        _ => {
            servers.insert(
                "guardrails".to_string(),
                json!({
                    "command": resolved_cmd,
                    "args": ["mcp", "--workspace", "."]
                }),
            );
        }
    }

    let pretty = serde_json::to_string_pretty(&root)?;
    fs::write(path, format!("{pretty}\n"))?;
    Ok(())
}

pub fn render_agents_managed_block(cfg: &GuardrailsConfig) -> String {
    let mut bullets = vec![
        "- Before concluding any task, run the `guardrails_check` MCP tool (or `guardrails check`).".to_string(),
    ];

    if cfg.is_rule_enabled("GR001") {
        let mut types = Vec::new();
        if cfg.gate.rust {
            types.push("`f64`/`f32`");
        }
        if cfg.gate.python {
            types.push("`float`");
        }
        if cfg.gate.typescript {
            types.push("`number`");
        }
        let type_str = if types.is_empty() {
            "floating-point types".to_string()
        } else {
            types.join("/")
        };
        bullets.push(format!(
            "- Never use {type_str} for money or quantities; use integer minor units or `Decimal`."
        ));
    }

    if cfg.is_rule_enabled("GR002") {
        bullets.push("- Every outbound HTTP/network client must set an explicit timeout.".to_string());
    }

    if cfg.is_rule_enabled("GR003") {
        bullets.push(
            "- Every mutating external API request must include an idempotency key.".to_string(),
        );
    }

    let gr004 = cfg.is_rule_enabled("GR004");
    let gr005 = cfg.is_rule_enabled("GR005");
    match (gr004, gr005) {
        (true, true) => {
            if cfg.gate.rust {
                bullets.push(
                    "- Do not swallow errors or leave `todo!()` / placeholder stubs.".to_string(),
                );
            } else {
                bullets.push("- Do not swallow errors or leave placeholder stubs.".to_string());
            }
        }
        (true, false) => {
            bullets.push("- Do not swallow errors or leave empty catch/except blocks.".to_string());
        }
        (false, true) => {
            if cfg.gate.rust {
                bullets.push("- Do not leave `todo!()` or placeholder stubs.".to_string());
            } else {
                bullets.push("- Do not leave placeholder stubs.".to_string());
            }
        }
        (false, false) => {}
    }

    for custom in &cfg.agents.custom_rules {
        let trimmed = custom.trim().trim_start_matches('-').trim();
        if !trimmed.is_empty() {
            bullets.push(format!("- {trimmed}"));
        }
    }

    format!(
        "{START_MARKER}\n## Deterministic Guardrails (Managed by `guardrails sync`)\n{}\n{END_MARKER}",
        bullets.join("\n")
    )
}

fn sync_agents_md(path: &Path, cfg: &GuardrailsConfig) -> anyhow::Result<()> {
    let managed_block = render_agents_managed_block(cfg);

    let updated = if path.exists() {
        let existing = fs::read_to_string(path)?;
        if let (Some(start), Some(end)) = (existing.find(START_MARKER), existing.find(END_MARKER)) {
            if start < end {
                let end_after = end + END_MARKER.len();
                format!("{}{}{}", &existing[..start], managed_block, &existing[end_after..])
            } else {
                format!("{existing}\n\n{managed_block}\n")
            }
        } else if existing.trim().is_empty() {
            format!("{managed_block}\n")
        } else {
            format!("{}\n\n{managed_block}\n", existing.trim_end())
        }
    } else {
        format!("# Agent Instructions\n\n{managed_block}\n")
    };

    fs::write(path, updated)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_is_idempotent_and_preserves_existing_content() {
        let dir = std::env::temp_dir().join(format!("guardrails_sync_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(
            dir.join(".mcp.json"),
            r#"{"mcpServers":{"other":{"command":"echo"}}}"#,
        )
        .unwrap();
        fs::write(
            dir.join("AGENTS.md"),
            "# Custom Team Rules\nAlways write tests.\n",
        )
        .unwrap();

        let cfg = GuardrailsConfig::default();
        sync_all(&dir, &cfg, false).unwrap();
        sync_all(&dir, &cfg, false).unwrap(); // run twice for idempotency

        let mcp: Value = serde_json::from_str(&fs::read_to_string(dir.join(".mcp.json")).unwrap()).unwrap();
        assert!(mcp["mcpServers"]["other"].is_object());
        assert!(mcp["mcpServers"]["guardrails"].is_object());
        assert!(!mcp["mcpServers"]["guardrails"]["command"].as_str().unwrap_or("").is_empty());

        let agents = fs::read_to_string(dir.join("AGENTS.md")).unwrap();
        assert!(agents.contains("# Custom Team Rules"));
        assert!(agents.contains("Always write tests."));
        assert_eq!(agents.matches(START_MARKER).count(), 1);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sync_preserves_custom_command_and_env_unless_forced() {
        let dir = std::env::temp_dir().join(format!("guardrails_sync_custom_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(
            dir.join(".mcp.json"),
            r#"{
  "mcpServers": {
    "guardrails": {
      "command": "C:\\tools\\guardrails-windows-x86_64.exe",
      "args": ["mcp", "--workspace", "."],
      "env": { "RUST_LOG": "info" }
    }
  }
}"#,
        )
        .unwrap();

        let mut cfg = GuardrailsConfig::default();
        cfg.sync.agents_md = false;

        sync_all(&dir, &cfg, false).unwrap();
        let mcp: Value = serde_json::from_str(&fs::read_to_string(dir.join(".mcp.json")).unwrap()).unwrap();
        assert_eq!(
            mcp["mcpServers"]["guardrails"]["command"].as_str().unwrap(),
            r"C:\tools\guardrails-windows-x86_64.exe"
        );
        assert_eq!(
            mcp["mcpServers"]["guardrails"]["env"]["RUST_LOG"].as_str().unwrap(),
            "info"
        );

        sync_all(&dir, &cfg, true).unwrap();
        let mcp_forced: Value = serde_json::from_str(&fs::read_to_string(dir.join(".mcp.json")).unwrap()).unwrap();
        assert_eq!(
            mcp_forced["mcpServers"]["guardrails"]["command"].as_str().unwrap(),
            resolve_mcp_command()
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn agents_md_adapts_to_disabled_rules_languages_and_custom_rules() {
        let mut cfg = GuardrailsConfig::default();
        cfg.gate.rust = false;
        cfg.gate.python = false;
        cfg.gate.typescript = true;
        cfg.rules.disabled = vec!["GR001".to_string(), "GR003".to_string()];
        cfg.agents.custom_rules = vec!["Keep React components pure.".to_string()];

        let block = render_agents_managed_block(&cfg);
        assert!(!block.contains("money or quantities"));
        assert!(!block.contains("idempotency key"));
        assert!(!block.contains("todo!()"));
        assert!(block.contains("explicit timeout"));
        assert!(block.contains("Do not swallow errors or leave placeholder stubs."));
        assert!(block.contains("- Keep React components pure."));
    }
}