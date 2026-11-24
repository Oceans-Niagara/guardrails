# Guardrails (aka SlopGuard)

**Deterministic AI & CI guardrail binary.**

Guardrails is an offline-first Rust CLI and MCP server developed by Oceans Niagara, LLC that enforces deterministic AST rules, quality gates, and resilience checks on your codebase without LLM dependencies.

- **Website & Licensing:** https://oceansniagara.com

## Install & Run Locally

- **Prebuilt Binaries (Windows, macOS, Linux):** Download the latest executable from [GitHub Releases](https://github.com/oceans-niagara/guardrails/releases).

```bash
# Or build from source with Cargo
cargo install --git https://github.com/oceans-niagara/guardrails

guardrails check --config guardrails.toml --format sarif
guardrails mcp

# Pro features (requires GUARDRAILS_LICENSE_KEY or --license-key)
guardrails license-check
guardrails resilience
```

## Licensing

For detailed information on **Free** and **Pro** licensing tiers verified via offline Ed25519-signed keys, please visit the [Oceans Niagara Website](https://oceansniagara.com).

- **Free ($0):** Core CLI, local AST rules, `guardrails.toml` quality gates, SARIF reporting, and stdio MCP server.
- **Pro ($19.99 one-time, perpetual):** Offline Ed25519 license key (delivered via email), `guardrails resilience` and chaos testing suite, and commercial/CI pipeline usage.

&copy; 2026 Oceans Niagara, LLC &bull; Questions: [connect@oceansniagara.com](mailto:connect@oceansniagara.com)
