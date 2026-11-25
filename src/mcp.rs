use serde_json::{json, Value};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub async fn run_mcp_stdio(workspace: PathBuf) -> anyhow::Result<()> {
    let stdin = BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();
    let mut lines = stdin.lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let id = req.get("id").cloned();
        let method = req["method"].as_str().unwrap_or("");

        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "guardrails", "version": env!("CARGO_PKG_VERSION") }
            })),
            "notifications/initialized" => continue,
            "tools/list" => Ok(json!({
                "tools": [
                    {
                        "name": "guardrails_check",
                        "description": "Run deterministic AST & unified lint/type guardrails before finishing edits.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": { "type": "string", "description": "Subpath to scan (optional)" }
                            }
                        }
                    }
                ]
            })),
            "tools/call" => {
                let tool_name = req["params"]["name"].as_str().unwrap_or("");
                match tool_name {
                    "guardrails_check" => {
                        let target = req["params"]["arguments"]["path"]
                            .as_str()
                            .map(|p| workspace.join(p))
                            .unwrap_or_else(|| workspace.clone());

                        let cfg = crate::config::GuardrailsConfig::load(&workspace, None)
                            .unwrap_or_default();

                        let mut findings = if cfg.ast.enabled {
                            crate::ast_rules::scan_workspace(&target, &cfg.ast.exclude)
                                .unwrap_or_default()
                        } else {
                            vec![]
                        };

                        findings.extend(
                            crate::gate::run_unified_gate(&target, &cfg.gate)
                                .await
                                .unwrap_or_default(),
                        );

                        findings.retain(|f| cfg.is_rule_enabled(&f.rule_id));

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

                        Ok(json!({
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&findings)?
                            }],
                            "isError": !findings.is_empty()
                        }))
                    }
                    _ => Err((-32601, "Unknown tool")),
                }
            }
            _ => Err((-32601, "Method not found")),
        };

        if let Some(id) = id {
            let resp = match result {
                Ok(res) => json!({ "jsonrpc": "2.0", "id": id, "result": res }),
                Err((code, msg)) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } }),
            };
            stdout.write_all(resp.to_string().as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}