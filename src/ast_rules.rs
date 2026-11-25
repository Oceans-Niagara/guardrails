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

fn uses_shell_true(matched: &str, _src: &str, _offset: usize) -> bool {
    matched.contains("shell=True") || matched.contains("shell = True")
}

fn not_in_rust_test_block(_matched: &str, src: &str, offset: usize) -> bool {
    !src[..offset.min(src.len())].contains("#[cfg(test)]")
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

    // 6. Universal security & unsafe execution
    EmbeddedRule {
        id: "GR006-UNSAFE-EVAL-TS",
        lang: Lang::TypeScript,
        severity: Severity::Error,
        pattern: "eval($$$ARGS)",
        message: "Dynamic `eval()` execution enables code injection",
        remediation: "Parse structured data (e.g. `JSON.parse`) or use an explicit lookup table instead of `eval()`.",
        predicate: None,
    },
    EmbeddedRule {
        id: "GR006-UNSAFE-FUNC-TS",
        lang: Lang::TypeScript,
        severity: Severity::Error,
        pattern: "new Function($$$ARGS)",
        message: "`new Function()` compiles arbitrary strings as executable code",
        remediation: "Replace dynamic code construction with static functions or data-driven dispatch.",
        predicate: None,
    },
    EmbeddedRule {
        id: "GR006-UNSAFE-EVAL-PY",
        lang: Lang::Python,
        severity: Severity::Error,
        pattern: "eval($$$ARGS)",
        message: "Dynamic `eval()` risks arbitrary code execution",
        remediation: "Use `ast.literal_eval()` for literals or `json.loads()` for JSON.",
        predicate: None,
    },
    EmbeddedRule {
        id: "GR006-UNSAFE-EXEC-PY",
        lang: Lang::Python,
        severity: Severity::Error,
        pattern: "exec($$$ARGS)",
        message: "Dynamic `exec()` risks arbitrary code execution",
        remediation: "Avoid `exec()` and use explicit functions or mappings.",
        predicate: None,
    },
    EmbeddedRule {
        id: "GR006-SHELL-INJECTION-PY",
        lang: Lang::Python,
        severity: Severity::Error,
        pattern: "subprocess.run($$$ARGS)",
        message: "`subprocess.run(..., shell=True)` risks command injection",
        remediation: "Pass an argument list with `shell=False` (the default).",
        predicate: Some(uses_shell_true),
    },
    EmbeddedRule {
        id: "GR006-SHELL-POPEN-PY",
        lang: Lang::Python,
        severity: Severity::Error,
        pattern: "subprocess.Popen($$$ARGS)",
        message: "`subprocess.Popen(..., shell=True)` risks command injection",
        remediation: "Pass an argument list with `shell=False` (the default).",
        predicate: Some(uses_shell_true),
    },

    // 7. Reliability / panic hygiene
    EmbeddedRule {
        id: "GR007-PANIC-UNWRAP-RUST",
        lang: Lang::Rust,
        severity: Severity::Warning,
        pattern: "$EXPR.unwrap()",
        message: "`.unwrap()` in production Rust code can panic at runtime",
        remediation: "Propagate errors with `?`, use `.unwrap_or*()`, or handle explicitly.",
        predicate: Some(not_in_rust_test_block),
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
        "ts" => Some((Lang::TypeScript, SupportLang::TypeScript)),
        "tsx" => Some((Lang::TypeScript, SupportLang::Tsx)),
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

fn has_token_with_prefix(line: &str, prefix: &str, min_tail_len: usize, uppercase_alnum_only: bool) -> bool {
    let mut search_from = 0;
    while let Some(idx) = line[search_from..].find(prefix) {
        let start = search_from + idx + prefix.len();
        let tail_len = line[start..]
            .chars()
            .take_while(|c| {
                if uppercase_alnum_only {
                    c.is_ascii_uppercase() || c.is_ascii_digit()
                } else {
                    c.is_ascii_alphanumeric() || *c == '_' || *c == '-'
                }
            })
            .count();
        if tail_len >= min_tail_len {
            return true;
        }
        search_from = start;
    }
    false
}

fn contains_hardcoded_secret(line: &str) -> bool {
    has_token_with_prefix(line, "sk_live_", 12, false)
        || has_token_with_prefix(line, "rk_live_", 12, false)
        || has_token_with_prefix(line, "ghp_", 20, false)
        || has_token_with_prefix(line, "github_pat_", 20, false)
        || has_token_with_prefix(line, "xoxb-", 12, false)
        || has_token_with_prefix(line, "AKIA", 16, true)
        || line.contains("-----BEGIN PRIVATE KEY-----")
        || line.contains("-----BEGIN RSA PRIVATE KEY-----")
}

fn is_test_or_example_path(rel: &str) -> bool {
    rel.starts_with("tests/")
        || rel.contains("/tests/")
        || rel.starts_with("examples/")
        || rel.contains("/examples/")
        || rel.ends_with("_test.rs")
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
    let skip_rust_unwrap = is_test_or_example_path(rel);
    for rule in RULES
        .iter()
        .filter(|r| std::mem::discriminant(&r.lang) == std::mem::discriminant(&lang))
    {
        if skip_rust_unwrap && rule.id == "GR007-PANIC-UNWRAP-RUST" {
            continue;
        }
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

    // Line-level AI placeholder comment & hardcoded secret checks
    let skip_secret_self_scan = rel.ends_with("ast_rules.rs");
    for (idx, line) in src.lines().enumerate() {
        if line.contains("guardrails-ignore") {
            continue;
        }
        if !skip_secret_self_scan && contains_hardcoded_secret(line) {
            findings.push(Finding {
                rule_id: "GR006-HARDCODED-SECRET".to_string(),
                tool: "guardrails-ast".to_string(),
                severity: Severity::Error,
                message: "Hardcoded secret or private key material detected in source".to_string(),
                file: rel.to_string(),
                start_line: idx + 1,
                start_col: 1,
                remediation: Some(
                    "Move credentials to environment variables or a secret manager.".to_string(),
                ),
            });
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
            let targets = match rule.lang {
                Lang::Rust => vec![SupportLang::Rust],
                Lang::TypeScript => vec![SupportLang::TypeScript, SupportLang::Tsx],
                Lang::Python => vec![SupportLang::Python],
            };
            for sg_lang in targets {
                assert!(
                    Pattern::try_new(rule.pattern, sg_lang).is_ok(),
                    "Rule {} has invalid AST pattern: {}",
                    rule.id,
                    rule.pattern
                );
            }
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
    fn valid_tsx_emits_no_syntax_error() {
        let src = "export function HoroscopeCard({ sign }: { sign: string }) {\n  return <div className=\"card\">{sign}</div>;\n}\n";
        let mut findings = Vec::new();
        scan_source(
            Lang::TypeScript,
            SupportLang::Tsx,
            "HoroscopeCard.tsx",
            src,
            &mut findings,
        );
        assert!(
            !findings.iter().any(|f| f.rule_id.starts_with("GR000-SYNTAX-ERROR")),
            "Unexpected syntax error on valid TSX: {findings:?}"
        );
    }

    #[test]
    fn flags_universal_security_and_rust_unwrap() {
        let ts_src = "const res = eval(userInput);\nconst key = \"sk_live_1234567890abcdef\";\n";
        let mut ts_findings = Vec::new();
        scan_source(Lang::TypeScript, SupportLang::TypeScript, "app.ts", ts_src, &mut ts_findings);
        assert!(ts_findings.iter().any(|f| f.rule_id == "GR006-UNSAFE-EVAL-TS"));
        assert!(ts_findings.iter().any(|f| f.rule_id == "GR006-HARDCODED-SECRET"));

        let py_src = "import subprocess\nsubprocess.run(cmd, shell=True)\n";
        let mut py_findings = Vec::new();
        scan_source(Lang::Python, SupportLang::Python, "runner.py", py_src, &mut py_findings);
        assert!(py_findings.iter().any(|f| f.rule_id == "GR006-SHELL-INJECTION-PY"));

        let rs_src = "fn prod() -> usize { \"1\".parse::<usize>().unwrap() }\n#[cfg(test)]\nmod tests {\n  #[test]\n  fn ok() { \"1\".parse::<usize>().unwrap(); }\n}\n";
        let mut rs_findings = Vec::new();
        scan_source(Lang::Rust, SupportLang::Rust, "src/lib.rs", rs_src, &mut rs_findings);
        let unwrap_lines: Vec<usize> = rs_findings
            .iter()
            .filter(|f| f.rule_id == "GR007-PANIC-UNWRAP-RUST")
            .map(|f| f.start_line)
            .collect();
        assert_eq!(unwrap_lines, vec![1]);
    }
}