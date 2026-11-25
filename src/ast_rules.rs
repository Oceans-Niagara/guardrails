use ast_grep_core::{Doc, Language, Node, Pattern};
use crate::sarif::{Finding, Severity};
use ast_grep_language::SupportLang;
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use std::collections::HashSet;
use std::path::Path;

#[derive(Clone, Copy)]
pub enum Lang {
    Rust,
    TypeScript,
    Python,
}

impl Lang {
    fn suffix(self) -> &'static str {
        match self {
            Lang::Rust => "RUST",
            Lang::TypeScript => "TS",
            Lang::Python => "PY",
        }
    }
}

struct EmbeddedRule {
    id: &'static str,
    lang: Lang,
    severity: Severity,
    pattern: &'static str,
    message: &'static str,
    remediation: &'static str,
    predicate: Option<fn(matched_text: &str, full_source: &str, byte_offset: usize) -> bool>,
}

const MONEY_KEYWORDS: &[&str] = &[
    "price", "amount", "total", "subtotal", "tax", "fee", "balance", "qty", "quantity", "cents",
];

fn is_money_identifier(matched: &str, _src: &str, _offset: usize) -> bool {
    let lower = matched.to_ascii_lowercase();
    MONEY_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

fn missing_timeout_in_call(matched: &str, _src: &str, _offset: usize) -> bool {
    !matched.contains("timeout")
}

fn missing_idempotency_in_scope(matched: &str, src: &str, offset: usize) -> bool {
    let start = offset.saturating_sub(300);
    let end = (offset + matched.len() + 300).min(src.len());
    let window = &src[start..end].to_ascii_lowercase();
    !(window.contains("idempotency") || window.contains("idempotent"))
}

const RULES: &[EmbeddedRule] = &[
    // 1. Float math on money / quantities
    EmbeddedRule {
        id: "GR001-FLOAT-MONEY-RUST",
        lang: Lang::Rust,
        severity: Severity::Error,
        pattern: "$VAR: f64",
        message: "Floating-point type `f64` used for monetary or quantity identifier",
        remediation: "Use integer minor units (i64 cents) or `rust_decimal::Decimal`.",
        predicate: Some(is_money_identifier),
    },
    EmbeddedRule {
        id: "GR001-FLOAT-MONEY-RUST-F32",
        lang: Lang::Rust,
        severity: Severity::Error,
        pattern: "$VAR: f32",
        message: "Floating-point type `f32` used for monetary or quantity identifier",
        remediation: "Use integer minor units (i64 cents) or `rust_decimal::Decimal`.",
        predicate: Some(is_money_identifier),
    },
    EmbeddedRule {
        id: "GR001-FLOAT-MONEY-PY",
        lang: Lang::Python,
        severity: Severity::Error,
        pattern: "$VAR: float",
        message: "Python `float` annotation used on monetary/quantity identifier",
        remediation: "Use `decimal.Decimal` or integer minor units.",
        predicate: Some(is_money_identifier),
    },
    EmbeddedRule {
        id: "GR001-FLOAT-MONEY-TS",
        lang: Lang::TypeScript,
        severity: Severity::Warning,
        pattern: "$A * $B",
        message: "Floating-point multiplication on monetary/quantity identifier",
        remediation: "Compute in integer minor units (cents) or a decimal library (e.g. `decimal.js`).",
        predicate: Some(is_money_identifier),
    },

    // 2. Missing network timeouts
    EmbeddedRule {
        id: "GR002-MISSING-TIMEOUT-RUST",
        lang: Lang::Rust,
        severity: Severity::Error,
        pattern: "reqwest::Client::new()",
        message: "`reqwest::Client::new()` has no default request timeout",
        remediation: "Use `reqwest::Client::builder().timeout(Duration::from_secs(10)).build()`.",
        predicate: None,
    },
    EmbeddedRule {
        id: "GR002-MISSING-TIMEOUT-TS",
        lang: Lang::TypeScript,
        severity: Severity::Error,
        pattern: "fetch($$$ARGS)",
        message: "`fetch()` called without an AbortSignal/timeout",
        remediation: "Pass `{ signal: AbortSignal.timeout(10_000) }` to `fetch()`.",
        predicate: Some(|m, _, _| !m.contains("signal") && !m.contains("timeout")),
    },
    EmbeddedRule {
        id: "GR002-MISSING-TIMEOUT-AXIOS",
        lang: Lang::TypeScript,
        severity: Severity::Error,
        pattern: "axios.post($$$ARGS)",
        message: "`axios.post()` called without explicit `timeout`",
        remediation: "Pass `{ timeout: 10000 }` in Axios request config.",
        predicate: Some(missing_timeout_in_call),
    },
    EmbeddedRule {
        id: "GR002-MISSING-TIMEOUT-PY",
        lang: Lang::Python,
        severity: Severity::Error,
        pattern: "requests.post($$$ARGS)",
        message: "`requests.post()` called without `timeout=` (can hang indefinitely)",
        remediation: "Pass `timeout=10` (or `(connect, read)` tuple).",
        predicate: Some(missing_timeout_in_call),
    },
    EmbeddedRule {
        id: "GR002-MISSING-TIMEOUT-HTTPX",
        lang: Lang::Python,
        severity: Severity::Error,
        pattern: "httpx.post($$$ARGS)",
        message: "`httpx.post()` called without explicit `timeout=`",
        remediation: "Pass `timeout=10.0` or configure `httpx.Client(timeout=10.0)`.",
        predicate: Some(missing_timeout_in_call),
    },

    // 3. Missing idempotency keys on mutating calls
    EmbeddedRule {
        id: "GR003-IDEMPOTENCY-TS",
        lang: Lang::TypeScript,
        severity: Severity::Warning,
        pattern: "fetch($URL, { method: 'POST', $$$REST })",
        message: "POST request missing visible idempotency key header",
        remediation: "Include an `Idempotency-Key` header for mutating API calls.",
        predicate: Some(missing_idempotency_in_scope),
    },
    EmbeddedRule {
        id: "GR003-IDEMPOTENCY-PY",
        lang: Lang::Python,
        severity: Severity::Warning,
        pattern: "requests.post($$$ARGS)",
        message: "POST request missing visible idempotency key header",
        remediation: "Include an `Idempotency-Key` header for mutating API calls.",
        predicate: Some(missing_idempotency_in_scope),
    },

    // 4. Swallowed errors
    EmbeddedRule {
        id: "GR004-SWALLOWED-ERR-RUST",
        lang: Lang::Rust,
        severity: Severity::Warning,
        pattern: "let _ = $EXPR;",
        message: "Potential swallowed Result/Option via `let _ = ...`",
        remediation: "Propagate with `?`, handle explicitly, or mark `// guardrails-ignore` if intentional.",
        predicate: None,
    },
    EmbeddedRule {
        id: "GR004-SWALLOWED-ERR-TS",
        lang: Lang::TypeScript,
        severity: Severity::Error,
        pattern: "try { $$$BODY } catch ($ERR) {}",
        message: "Empty `catch` block silently swallows exception",
        remediation: "Log, rethrow, or return a typed error.",
        predicate: None,
    },
    EmbeddedRule {
        id: "GR004-SWALLOWED-ERR-PY",
        lang: Lang::Python,
        severity: Severity::Error,
        pattern: "try:\n    $$$BODY\nexcept Exception:\n    pass",
        message: "`except Exception: pass` silently swallows failures",
        remediation: "Log the exception or narrow and handle the expected error type.",
        predicate: None,
    },

    // 5. AI placeholder stubs
    EmbeddedRule {
        id: "GR005-AI-STUB-RUST-TODO",
        lang: Lang::Rust,
        severity: Severity::Error,
        pattern: "todo!($$$ARGS)",
        message: "Unfinished `todo!()` macro left in code",
        remediation: "Implement behavior before merge.",
        predicate: None,
    },
    EmbeddedRule {
        id: "GR005-AI-STUB-RUST-UNIMPL",
        lang: Lang::Rust,
        severity: Severity::Error,
        pattern: "unimplemented!($$$ARGS)",
        message: "Unfinished `unimplemented!()` macro left in code",
        remediation: "Implement behavior before merge.",
        predicate: None,
    },
    EmbeddedRule {
        id: "GR005-AI-STUB-TS",
        lang: Lang::TypeScript,
        severity: Severity::Error,
        pattern: "throw new Error(\"not implemented\")",
        message: "AI/developer placeholder Error(\"not implemented\") left in code",
        remediation: "Implement behavior before merge.",
        predicate: None,
    },
    EmbeddedRule {
        id: "GR005-AI-STUB-PY",
        lang: Lang::Python,
        severity: Severity::Error,
        pattern: "raise NotImplementedError($$$ARGS)",
        message: "Unfinished `NotImplementedError` placeholder left in code",
        remediation: "Implement behavior before merge.",
        predicate: None,
    },
];

fn build_exclude_set(patterns: &[String]) -> anyhow::Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        builder.add(Glob::new(p)?);
    }
    Ok(builder.build()?)
}

fn detect_lang(path: &Path) -> Option<(Lang, SupportLang)> {
    match path.extension()?.to_str()? {
        "rs" => Some((Lang::Rust, SupportLang::Rust)),
        "ts" | "tsx" => Some((Lang::TypeScript, SupportLang::TypeScript)),
        "py" => Some((Lang::Python, SupportLang::Python)),
        _ => None,
    }
}

fn collect_error_nodes<'r, D: Doc>(node: Node<'r, D>, out: &mut Vec<(usize, usize)>) {
    if node.is_error() {
        let pos = node.start_pos();
        out.push((pos.line() + 1, pos.column(&node) + 1));
        return;
    }
    for child in node.children() {
        collect_error_nodes(child, out);
    }
}

fn scan_source(
    lang: Lang,
    sg_lang: SupportLang,
    rel: &str,
    src: &str,
    findings: &mut Vec<Finding>,
) {
    let root_ast = sg_lang.ast_grep(src);

    // 0. Syntax / parse errors (e.g. stray markdown fences or truncated LLM output)
    let mut error_locs = Vec::new();
    collect_error_nodes(root_ast.root(), &mut error_locs);
    let mut seen_lines = HashSet::new();
    for (line, col) in error_locs {
        if !seen_lines.insert(line) {
            continue;
        }
        findings.push(Finding {
            rule_id: format!("GR000-SYNTAX-ERROR-{}", lang.suffix()),
            tool: "guardrails-ast".to_string(),
            severity: Severity::Error,
            message: "Syntax/parse error detected; file may contain invalid syntax or stray markdown fences (```)."
                .to_string(),
            file: rel.to_string(),
            start_line: line,
            start_col: col,
            remediation: Some(
                "Fix the syntax error or remove stray markdown code fences before continuing."
                    .to_string(),
            ),
        });
    }

    // AST structural rules
    for rule in RULES
        .iter()
        .filter(|r| std::mem::discriminant(&r.lang) == std::mem::discriminant(&lang))
    {
        let pat = match Pattern::try_new(rule.pattern, sg_lang) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Skipping invalid pattern {}: {e:?}", rule.id);
                continue;
            }
        };
        for m in root_ast.root().find_all(pat) {
            let text = m.text();
            let range = m.range();
            if let Some(pred) = rule.predicate {
                if !pred(&text, src, range.start) {
                    continue;
                }
            }
            let start_pos = m.start_pos();
            let line_idx = start_pos.line();
            if src.lines().nth(line_idx).unwrap_or("").contains("guardrails-ignore") {
                continue;
            }
            findings.push(Finding {
                rule_id: rule.id.to_string(),
                tool: "guardrails-ast".to_string(),
                severity: rule.severity.clone(),
                message: rule.message.to_string(),
                file: rel.to_string(),
                start_line: line_idx + 1,
                start_col: start_pos.column(m.get_node()) + 1,
                remediation: Some(rule.remediation.to_string()),
            });
        }
    }

    // Line-level AI placeholder comment check
    for (idx, line) in src.lines().enumerate() {
        if line.contains("guardrails-ignore") {
            continue;
        }
        let trimmed = line.trim();
        let is_comment = trimmed.starts_with("//") || trimmed.starts_with('#');
        if is_comment
            && (trimmed.contains("TODO:") || trimmed.contains("FIXME:") || trimmed.contains("PLACEHOLDER"))
        {
            findings.push(Finding {
                rule_id: "GR005-AI-COMMENT-TODO".to_string(),
                tool: "guardrails-ast".to_string(),
                severity: Severity::Warning,
                message: "Unresolved TODO/FIXME/PLACEHOLDER comment left in code".to_string(),
                file: rel.to_string(),
                start_line: idx + 1,
                start_col: 1,
                remediation: Some("Resolve placeholder or convert into a tracked issue.".to_string()),
            });
        }
    }
}

pub fn scan_workspace(root: &Path, exclude: &[String]) -> anyhow::Result<Vec<Finding>> {
    let excludes = build_exclude_set(exclude)?;
    let mut findings = Vec::new();

    for entry in WalkBuilder::new(root).hidden(true).git_ignore(true).build() {
        let entry = match entry {
            Ok(e) if e.file_type().map(|t| t.is_file()).unwrap_or(false) => e,
            _ => continue,
        };
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");

        if excludes.is_match(&rel) {
            continue;
        }

        let Some((lang, sg_lang)) = detect_lang(path) else {
            continue;
        };
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };

        scan_source(lang, sg_lang, &rel, &src, &mut findings);
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_embedded_patterns_compile() {
        for rule in RULES {
            let sg_lang = match rule.lang {
                Lang::Rust => SupportLang::Rust,
                Lang::TypeScript => SupportLang::TypeScript,
                Lang::Python => SupportLang::Python,
            };
            assert!(
                Pattern::try_new(rule.pattern, sg_lang).is_ok(),
                "Rule {} has invalid AST pattern: {}",
                rule.id,
                rule.pattern
            );
        }
    }

    #[test]
    fn flags_stray_markdown_fence_as_syntax_error() {
        let src = "```typescript\nasync function chargeCustomer(amount: number, cardToken: string) {\n    const priceCents: number = 1999;\n    return { amount: priceCents, cardToken };\n}\n";
        let mut findings = Vec::new();
        scan_source(
            Lang::TypeScript,
            SupportLang::TypeScript,
            "payment_client.ts",
            src,
            &mut findings,
        );
        assert!(
            findings.iter().any(|f| f.rule_id == "GR000-SYNTAX-ERROR-TS" && f.start_line == 1),
            "Expected GR000-SYNTAX-ERROR-TS at line 1, got: {findings:?}"
        );
    }

    #[test]
    fn valid_typescript_emits_no_syntax_error() {
        let src = "async function ok(cardToken: string) {\n    const priceCents: number = 1999;\n    return { priceCents, cardToken };\n}\n";
        let mut findings = Vec::new();
        scan_source(
            Lang::TypeScript,
            SupportLang::TypeScript,
            "ok.ts",
            src,
            &mut findings,
        );
        assert!(
            !findings.iter().any(|f| f.rule_id.starts_with("GR000-SYNTAX-ERROR")),
            "Unexpected syntax error on valid TS: {findings:?}"
        );
    }
}