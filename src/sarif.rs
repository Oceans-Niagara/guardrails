use serde::Serialize;

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Note,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub tool: String,
    pub severity: Severity,
    pub message: String,
    pub file: String,
    pub start_line: usize,
    pub start_col: usize,
    pub remediation: Option<String>,
}

pub fn to_sarif(findings: &[Finding]) -> serde_json::Value {
    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Note => "note",
            };
            serde_json::json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file },
                        "region": {
                            "startLine": f.start_line.max(1),
                            "startColumn": f.start_col.max(1)
                        }
                    }
                }]
            })
        })
        .collect();

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "guardrails",
                    "version": env!("CARGO_PKG_VERSION")
                }
            },
            "results": results
        }]
    })
}