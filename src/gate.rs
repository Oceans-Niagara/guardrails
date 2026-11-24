use crate::config::GateConfig;
use crate::sarif::{Finding, Severity};
use std::path::Path;
use tokio::process::Command;

pub async fn run_unified_gate(root: &Path, gate_cfg: &GateConfig) -> anyhow::Result<Vec<Finding>> {
    let mut all = Vec::new();

    if gate_cfg.rust && root.join("Cargo.toml").exists() {
        all.extend(run_clippy(root).await?);
    }
    if gate_cfg.typescript && root.join("package.json").exists() && root.join("tsconfig.json").exists() {
        all.extend(run_tsc(root).await?);
    }
    if gate_cfg.python && root.join("pyproject.toml").exists() {
        all.extend(run_ruff(root).await?);
        all.extend(run_mypy(root).await?);
    }

    Ok(all)
}

async fn run_clippy(root: &Path) -> anyhow::Result<Vec<Finding>> {
    let Ok(out) = Command::new("cargo")
        .args(["clippy", "--all-targets", "--message-format=json"])
        .current_dir(root)
        .output()
        .await
    else {
        return Ok(vec![]);
    };

    let mut findings = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        if v["reason"] != "compiler-message" {
            continue;
        }
        let msg = &v["message"];
        let Some(span) = msg["spans"].as_array().and_then(|s| s.first()) else { continue };
        let level = msg["level"].as_str().unwrap_or("warning");
        if level == "help" {
            continue;
        }

        let severity = match level {
            "error" => Severity::Error,
            "note" => Severity::Note,
            _ => Severity::Warning,
        };

        findings.push(Finding {
            rule_id: msg["code"]["code"].as_str().unwrap_or("clippy").to_string(),
            tool: "clippy".to_string(),
            severity,
            message: msg["message"].as_str().unwrap_or("").to_string(),
            file: span["file_name"].as_str().unwrap_or("").replace('\\', "/"),
            start_line: span["line_start"].as_u64().unwrap_or(1) as usize,
            start_col: span["column_start"].as_u64().unwrap_or(1) as usize,
            remediation: None,
        });
    }
    Ok(findings)
}

async fn run_tsc(root: &Path) -> anyhow::Result<Vec<Finding>> {
    let npx = if cfg!(windows) { "npx.cmd" } else { "npx" };
    let Ok(out) = Command::new(npx)
        .args(["--no-install", "tsc", "--noEmit", "--pretty", "false"])
        .current_dir(root)
        .output()
        .await
    else {
        return Ok(vec![]);
    };

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let mut findings = Vec::new();
    for line in combined.lines() {
        if let Some(f) = parse_tsc_line(line) {
            findings.push(f);
        }
    }
    Ok(findings)
}

/// Parses lines shaped like: `src/index.ts(12,5): error TS2322: Type 'string' ...`
fn parse_tsc_line(line: &str) -> Option<Finding> {
    let (loc_part, rest) = line.split_once("): ")?;
    let (file_part, coords) = loc_part.rsplit_once('(')?;
    let (line_s, col_s) = coords.split_once(',')?;
    let start_line: usize = line_s.trim().parse().ok()?;
    let start_col: usize = col_s.trim().parse().ok()?;

    let (kind_and_code, message) = rest.split_once(": ")?;
    let (kind, code) = kind_and_code.split_once(' ')?;

    let severity = match kind {
        "error" => Severity::Error,
        "warning" => Severity::Warning,
        _ => Severity::Note,
    };

    Some(Finding {
        rule_id: code.to_string(),
        tool: "tsc".to_string(),
        severity,
        message: message.trim().to_string(),
        file: file_part.trim().replace('\\', "/"),
        start_line,
        start_col,
        remediation: None,
    })
}

async fn run_ruff(root: &Path) -> anyhow::Result<Vec<Finding>> {
    let Ok(out) = Command::new("ruff")
        .args(["check", "--output-format=json", "."])
        .current_dir(root)
        .output()
        .await
    else {
        return Ok(vec![]);
    };

    let mut findings = Vec::new();
    if let Ok(items) = serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout) {
        for item in items {
            findings.push(Finding {
                rule_id: item["code"].as_str().unwrap_or("ruff").to_string(),
                tool: "ruff".to_string(),
                severity: Severity::Error,
                message: item["message"].as_str().unwrap_or("").to_string(),
                file: item["filename"].as_str().unwrap_or("").replace('\\', "/"),
                start_line: item["location"]["row"].as_u64().unwrap_or(1) as usize,
                start_col: item["location"]["column"].as_u64().unwrap_or(1) as usize,
                remediation: None,
            });
        }
    }
    Ok(findings)
}

async fn run_mypy(root: &Path) -> anyhow::Result<Vec<Finding>> {
    let Ok(out) = Command::new("mypy")
        .args(["--output=json", "."])
        .current_dir(root)
        .output()
        .await
    else {
        return Ok(vec![]);
    };

    let mut findings = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let sev_str = v["severity"].as_str().unwrap_or("error");
        let severity = match sev_str {
            "error" => Severity::Error,
            "warning" => Severity::Warning,
            _ => Severity::Note,
        };

        findings.push(Finding {
            rule_id: v["code"].as_str().unwrap_or("mypy").to_string(),
            tool: "mypy".to_string(),
            severity,
            message: v["message"].as_str().unwrap_or("").to_string(),
            file: v["file"].as_str().unwrap_or("").replace('\\', "/"),
            start_line: v["line"].as_u64().unwrap_or(1) as usize,
            start_col: v["column"].as_u64().unwrap_or(1) as usize,
            remediation: None,
        });
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tsc_error_and_warning_lines() {
        let err = parse_tsc_line(
            "src/index.ts(12,5): error TS2322: Type 'string' is not assignable to type 'number'.",
        )
        .expect("should parse TS error");
        assert_eq!(err.rule_id, "TS2322");
        assert_eq!(err.file, "src/index.ts");
        assert_eq!(err.start_line, 12);
        assert_eq!(err.start_col, 5);
        assert!(matches!(err.severity, Severity::Error));

        let warn = parse_tsc_line(
            "src\\app.ts(3,1): warning TS6133: 'x' is declared but its value is never read.",
        )
        .expect("should parse TS warning");
        assert_eq!(warn.file, "src/app.ts");
        assert!(matches!(warn.severity, Severity::Warning));

        assert!(parse_tsc_line("Found 2 errors in 2 files.").is_none());
    }
}