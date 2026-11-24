use serde_json::{json, Map, Value};
use std::fs;
use std::path::Path;

const START_MARKER: &str = "<!-- GUARDRAILS:START -->";
const END_MARKER: &str = "<!-- GUARDRAILS:END -->";

pub fn sync_all(workspace: &Path, sync_mcp: bool, sync_agents: bool) -> anyhow::Result<()> {
    if sync_mcp {
        sync_mcp_json(&workspace.join(".mcp.json"))?;
    }
    if sync_agents {
        sync_agents_md(&workspace.join("AGENTS.md"))?;
    }
    Ok(())
}

fn sync_mcp_json(path: &Path) -> anyhow::Result<()> {
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

    servers.insert(
        "guardrails".to_string(),
        json!({
            "command": "guardrails",
            "args": ["mcp", "--workspace", "."]
        }),
    );

    let pretty = serde_json::to_string_pretty(&root)?;
    fs::write(path, format!("{pretty}\n"))?;
    Ok(())
}

fn sync_agents_md(path: &Path) -> anyhow::Result<()> {
    let managed_block = format!(
        "{START_MARKER}
## Deterministic Guardrails (Managed by `guardrails sync`)
- Before concluding any task, run the `guardrails_check` MCP tool (or `guardrails check`).
- Never use `f64`/`float` for money or quantities; use integer minor units or `Decimal`.
- Every outbound HTTP/network client must set an explicit timeout.
- Every mutating external API request must include an idempotency key.
- Do not swallow errors or leave `todo!()` / placeholder stubs.
{END_MARKER}"
    );

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

        sync_all(&dir, true, true).unwrap();
        sync_all(&dir, true, true).unwrap(); // run twice for idempotency

        let mcp: Value = serde_json::from_str(&fs::read_to_string(dir.join(".mcp.json")).unwrap()).unwrap();
        assert!(mcp["mcpServers"]["other"].is_object());
        assert!(mcp["mcpServers"]["guardrails"].is_object());

        let agents = fs::read_to_string(dir.join("AGENTS.md")).unwrap();
        assert!(agents.contains("# Custom Team Rules"));
        assert!(agents.contains("Always write tests."));
        assert_eq!(agents.matches(START_MARKER).count(), 1);

        let _ = fs::remove_dir_all(&dir);
    }
}